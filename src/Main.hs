-- Ilya Prokin <isprokin@gmail.com>
-- Code Excercise - Tsuru Capital Application

{-
 REFERENCES
    pcap format description
        https://wiki.wireshark.org/Development/LibpcapFileFormat#File_Format
        https://delog.wordpress.com/2010/12/13/information-in-a-pcap-file-with-a-single-udp-packet/
        https://www.elvidence.com.au/understanding-time-stamps-in-packet-capture-data-pcap-files/
    UDP description
        https://en.wikipedia.org/wiki/User_Datagram_Protocol
        https://en.wikibooks.org/wiki/Communication_Networks/TCP_and_UDP_Protocols
    Reading pcap
        https://serverfault.com/questions/38626/how-can-i-read-pcap-files-in-a-friendly-format
        tcpdump -qns 0 -X -r mdf-kospi200.20110216-0.pcap | less
        Wireshark-gtk
    Dealing with Binary in Haskell
        https://wiki.haskell.org/Dealing_with_binary_data
        https://hackage.haskell.org/package/binary-0.9.0.0/docs/Data-Binary-Get.html
        http://hackage.haskell.org/package/binary-0.8.5.1/docs/src/Data.Binary.Get.html#runGetIncremental
-}

module Main(main) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Internal as L (chunk, ByteString(Chunk, Empty))
import qualified Data.ByteString.Lazy.Char8 as CL

import Data.Binary.Get (Get, Decoder (Done, Partial, Fail), runGetIncremental, getWord32le, getWord16be, getWord8, getLazyByteString, skip, isEmpty)
import Data.Word (Word32, Word16, Word8)
import GHC.Int (Int64)

import Data.Maybe (Maybe, fromJust, isJust)
import Data.Function (on)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Data.Time.Clock (UTCTime)
import Data.List (intercalate, sortBy, groupBy)
import Data.Char (ord)

import System.Environment (getArgs)

-- CONSTANTS

--lenEthHeader  = 14
--lenIP4Header  = 20
idString        = "B6034" :: String
endOfMessage    = 255     :: Word8
lenQuotePack    = 215     :: Int

lenPcapGlobH    = 24      :: Int64
lenPcapH        = 16      :: Int
lenEthAndIP4    = 34      :: Int
lenUDPh         = 8       :: Int
lenHeaders      = lenPcapH + lenEthAndIP4 + lenUDPh

pcapTsUsecUnits = 1e-6    :: Double -- to transform microseconds to seconds

-- DATA

data HeaderPcapPacket = HeaderPcapPacket
    { tsSecPcap   :: Word32
    , tsUsecPcap  :: Word32
    , inclLenPcap :: Word32
    , origLenPcap :: Word32
    } deriving (Show)


data HeaderUDPpacket = HeaderUDPpacket
    { sourcePortUDP :: Word16
    , destPortUDP   :: Word16
    , dataLenUDP    :: Word16
    , chkSumUDP     :: Word16
    } deriving (Show)


data ContentQuotePacket = ContentQuotePacket
    { issueCodeC  :: String
    , bidsC       :: [PriceVol]
    , asksC       :: [PriceVol]
    , acceptTimeC :: String
    } deriving Show


data PriceVol = PriceVol
    { price :: Double
    , vol   :: Double
    }
instance Show PriceVol where
    show x = show (vol x) ++ "@" ++ show (price x)


data DataLine = DataLine
    { packetTimestamp :: Double
    , acceptTime      :: String
    , issueCode       :: String
    , bids            :: [PriceVol]
    , asks            :: [PriceVol]
    }
instance Show DataLine where
    show x = intercalate sep
        [ show $ posixSecondsToUTCTime $ realToFrac $ packetTimestamp x
        , acceptTime x
        , issueCode x
        , intercalate sep $ map show $ bids x
        , intercalate sep $ map show $ asks x
        ]
        where sep = "\t"


-- FUNCTIONS

splitEvery :: Int -> [a] -> [[a]]
splitEvery n = takeWhile (not . null) . map (take n) . iterate (drop n)

-- Binary data parsers

getPriceVol :: Get PriceVol
getPriceVol = do
    price <- getLazyByteString 5
    vol   <- getLazyByteString 7
    return PriceVol
        { price = read (CL.unpack price) :: Double
        , vol   = read (CL.unpack vol)   :: Double
        }

getPriceVolAll :: Get [PriceVol]
getPriceVolAll = mapM (const getPriceVol) [1..5]


getHeaderPcapPacket :: Get HeaderPcapPacket
getHeaderPcapPacket = do
    tsSec   <- getWord32le
    tsUsec  <- getWord32le
    inclLen <- getWord32le
    origLen <- getWord32le
    return $ HeaderPcapPacket tsSec tsUsec inclLen origLen


getHeaderUDP :: Get HeaderUDPpacket
getHeaderUDP = do
    sourcePort <- getWord16be
    destPort   <- getWord16be
    totalLen   <- getWord16be
    chkSum     <- getWord16be
    return $ HeaderUDPpacket sourcePort destPort (totalLen-8) chkSum


getContentQuotePacket :: Get ContentQuotePacket
getContentQuotePacket = do
    issueCode  <- getLazyByteString 12
    -- SKIP  Issue seq.-no. 3, Market Status Type 2, Total bid quote volume 7
    skip 12
    bids       <- getPriceVolAll
    -- SKIP  Total ask quote volume 7
    skip 7
    asks       <- getPriceVolAll
    -- SKIP  No. of best bid/ask valid quotes 50
    skip 50
    acceptTime <- getLazyByteString 8
    return ContentQuotePacket
        { issueCodeC  = CL.unpack issueCode
        , bidsC       = bids
        , asksC       = asks
        , acceptTimeC = CL.unpack acceptTime
        }


getDataLine :: Get (Maybe DataLine)
getDataLine = do
    headerPcap <- getHeaderPcapPacket
    -- Read header and see if data packet is of interest to us
    let pcapPackLen = fromIntegral $ inclLenPcap headerPcap
    if pcapPackLen /= lenEthAndIP4 + lenUDPh + lenQuotePack
        -- If packet has a wrong size skip it
       then do
           skip pcapPackLen
           return Nothing
       else do
           -- Read assuming it's a good packet --
           skip lenEthAndIP4
           headerUDP  <- getHeaderUDP
           let lenUDP = fromIntegral $ dataLenUDP headerUDP
           dataId     <- getLazyByteString 5
           contentP   <- getContentQuotePacket
           eOm        <- getWord8
           -- Check if assumption was sane
           -- If it wasn't skip this packet
           let isGood =
                   (CL.unpack dataId == idString)     && -- indeed target packet
                   (lenUDP           == lenQuotePack) && -- has length of target
                   (eOm              == endOfMessage)    -- terminated ok
           if isGood
              then do
                  let timeNicer = intercalate ":" . splitEvery 2
                      dataL = DataLine
                          { packetTimestamp =
                              fromIntegral (tsSecPcap headerPcap)
                              + fromIntegral (tsUsecPcap headerPcap) * pcapTsUsecUnits
                          , acceptTime = timeNicer $ acceptTimeC contentP
                          , issueCode  = issueCodeC contentP
                          , bids       = reverse (bidsC contentP)
                          , asks       = asksC contentP
                          }
                  return (Just dataL)
              else
                  return Nothing

-- Incremental parser for the whole binary stream

-- Modified from https://hackage.haskell.org/package/binary-0.9.0.0/docs/Data-Binary-Get.html
getDataLines :: BL.ByteString -> [DataLine]
getDataLines input0 = map fromJust $ filter isJust $ go decoder input0
  where
      decoder = runGetIncremental getDataLine
      go :: Decoder (Maybe DataLine) -> BL.ByteString -> [Maybe DataLine]
      go (Done leftover _ d) input =
          d : go decoder (L.chunk leftover input)
      go (Partial k) input =
          go (k . takeHeadChunk $ input) (dropHeadChunk input)
      go Fail{} _ = []

-- Modified from https://hackage.haskell.org/package/binary-0.9.0.0/docs/Data-Binary-Get.html
takeHeadChunk :: BL.ByteString -> Maybe B.ByteString
takeHeadChunk lbs =
    case lbs of
      (L.Chunk bs _) -> Just bs
      _              -> Nothing

-- Modified from https://hackage.haskell.org/package/binary-0.9.0.0/docs/Data-Binary-Get.html
dropHeadChunk :: BL.ByteString -> BL.ByteString
dropHeadChunk lbs =
    case lbs of
      (L.Chunk _ lbs') -> lbs'
      _                -> L.Empty

-- Reordering
-- Group by Timestamp with bins of size acceptanceDelay [seconds].
-- Inside each group (each time bin), sort by acceptTime
-- This leaves border parts between groups unsorted
-- To solve this, we can repeat grouping and sorting.
-- Using bins of the same size, but shifted by half of acceptanceDelay, we can sort around borders between groups.
-- This is not the most efficient way, but it will work as long as acceptanceDelay is selected well for the data.
reorder :: [DataLine] -> [DataLine]
reorder = reorderS (acceptanceDelay `quot` 2) . reorderS 0
    where
        reorderS :: Integer -> [DataLine] -> [DataLine]
        reorderS shift  = concatMap sortGroup . grouped shift
        sortGroup       = sortBy (compare `on` acceptTime)
        grouped  :: Integer -> [DataLine] -> [[DataLine]]
        grouped shift   = groupBy ((==) `on` timeBin shift)
            where timeBin shift =
                    (`quot` acceptanceDelay) .  (+shift) . truncate . packetTimestamp
        acceptanceDelay = 2 -- [seconds]. Choose so that it is even

-- User interaction

helpMessage :: String
helpMessage = 
    "Please call with:\n"++
    indent ++ myName ++ " {file}\n"++
    "Alternatively, if you want to reorder records, call with:\n"++
    indent ++ myName ++ " -r {file}"
    where myName = "pcapKospi200"
          indent = "\t"

readTransformPrint :: ([DataLine] -> [DataLine]) -> (BL.ByteString -> BL.ByteString) -> String -> IO ()
readTransformPrint transformD transformC f =
    let printL      = mapM_ print
        rP contents = getDataLines contentsWithoutGlobalPcap
            where contentsWithoutGlobalPcap = BL.drop lenPcapGlobH contents
     in do
        c <- BL.readFile f
        printL $ transformD $ rP (transformC c)

main :: IO ()
main = do
    args <- getArgs
    case args of
      []          -> putStrLn helpMessage
      -- Run with reordering
      (f:"-r":_)  -> readTransformPrint reorder id f
      ("-r":f:_)  -> readTransformPrint reorder id f
      -- TEST with an input file transformed to the infinite file
      ("-tr":f:_) -> readTransformPrint reorder BL.cycle f
      ("-t":f:_)  -> readTransformPrint id BL.cycle f
      -- Run as usual
      (f:_)       -> readTransformPrint id id f
