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
    Dealing with Binary in Haskell
        https://wiki.haskell.org/Dealing_with_binary_data
        https://hackage.haskell.org/package/binary-0.9.0.0/docs/Data-Binary-Get.html
-}

module Main where

import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy.Char8 as CL
import Data.Binary.Get (Get, runGet, getWord32le, getWord16be, getWord8, getLazyByteString, skip, isEmpty)
import Data.Word (Word64, Word32, Word16, Word8)
import Data.Int (Int32)
import Data.Char (ord)
import Data.Maybe
import Data.List (intercalate)

import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Data.Time.Clock (UTCTime)

import System.Environment (getArgs)

--lenEthHeader = 14
--lenIP4Header = 20
lenEthAndIP4 = 34
idString = "B6034"
lenPack  = 215
breakerBString = BL.pack $ map (fromIntegral . ord) idString
endOfMessage = 255 :: Word8


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
    show x = (show $ vol x) ++ "@" ++ (show $ price x)


data DataLine = DataLine
    { packetTime :: Integer
    , acceptTime :: String
    , issueCode  :: String
    , bids       :: [PriceVol]
    , asks       :: [PriceVol]
    }
instance Show DataLine where
    show x = intercalate sep $
        [ show $ posixSecondsToUTCTime $ fromIntegral $ packetTime x
        , acceptTime x
        , issueCode x
        , intercalate sep $ map show $ bids x
        , intercalate sep $ map show $ asks x
        ]
        where sep = "\t"


splitEvery :: Int -> [a] -> [[a]]
splitEvery n = takeWhile (not.null) . map (take n) . iterate (drop n)


getPriceVol :: Get PriceVol
getPriceVol = do
    price <- getLazyByteString 5
    vol   <- getLazyByteString 7
    return PriceVol
        { price = read (CL.unpack price) :: Double
        , vol   = read (CL.unpack vol) :: Double
        }

getPriceVolAll :: Get [PriceVol]
getPriceVolAll = mapM (\_ -> getPriceVol) [1..5]

{-
data HeaderPcapGlobal = HeaderPcapGlobal
    { magicNumber  :: Word32
    , versionMajor :: Word16
    , versionMinor :: Word16
    , thisZone     :: Int32
    , sigFigs      :: Word32
    , snapLen      :: Word32
    , network      :: Word32
    } deriving (Show)
-}

{-
getHeaderPcapGlobal :: Get HeaderPcapGlobal
getHeaderPcapGlobal = do
    magicNumler  <- getWord32le
    versionMajor <- getWord16le
    versionMinor <- getWord16le
    thisZone     <- getInt32le
    sigFigs      <- getWord32le
    snapLen      <- getWord32le
    network      <- getWord32le
    return $ HeaderPcapGlobal
        { magicNumber  = magicNumber
        , versionMajor = versionMajor
        , versionMinor = versionMinor
        , thisZone     = thisZone
        , sigFigs      = sigFigs
        , snapLen      = snapLen
        , network      = network
        }
-}

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
    --SKIP    Issue seq.-no. 3, Market Status Type 2, Total bid quote volume 7
    skip 12
    bids       <- getPriceVolAll
    -- SKIP Total ask quote volume 7
    skip 7
    asks       <- getPriceVolAll
    -- SKIP     No. of best bid/ask valid quotes 50
    skip 50
    acceptTime <- getLazyByteString 8
    return $ ContentQuotePacket
        { issueCodeC  = CL.unpack issueCode
        , bidsC       = bids
        , asksC       = asks
        , acceptTimeC = CL.unpack acceptTime
        }

getDataLine :: Get (Int, Maybe DataLine)
getDataLine = do
    headerPcap <- getHeaderPcapPacket
    skip lenEthAndIP4
    headerUDP  <- getHeaderUDP
    let lenUDP = fromIntegral $ dataLenUDP headerUDP
    dataId     <- getLazyByteString 5
    -- read only packets we're looking for, skip otherwise
    if CL.unpack dataId == idString && lenUDP == lenPack
       then do
           contentP   <- getContentQuotePacket
           let timeNicer = (intercalate ":") . (splitEvery 2)
               dataL =
                   DataLine
                       { packetTime = fromIntegral $ tsSecPcap headerPcap
                       , acceptTime = timeNicer $ acceptTimeC contentP
                       , issueCode  = issueCodeC contentP
                       , bids       = reverse (bidsC contentP)
                       , asks       = asksC contentP
                       }
           eOm <- getWord8
           if eOm == endOfMessage
              then return (lenUDP, (Just dataL))
              else error "Bad termination !!!"--return (lenUDP, Nothing)
       else do
           skip lenUDP
           return (lenUDP, Nothing)


getData1 :: Get [(Int, Maybe DataLine)]
getData1 = do
  empty <- isEmpty
  if empty
    then return []
    else do line  <- getDataLine
            lines <- getData1
            return (line:lines)

getData :: BL.ByteString -> [DataLine]
getData c = map fromJust $ filter isJust $ gd (BL.length c) c
    where
        gd n c | n > lenM  = dataL : gd (n-lenA) (BL.drop lenA c)
               | otherwise = []
               where
                   lenU = foldl (+) 0 $
                       [ lenPcapH
                       , fromIntegral lenEthAndIP4
                       , lenUDPh
                       ]
                   lenA      = lenU + fromIntegral lenUDPd
                   lenM      = lenU + lenMaxUDP
                   lenPcapH  = 16
                   lenUDPh   = 8
                   lenMaxUDP = 600
                   (lenUDPd, dataL) = runGet getDataLine c


test4 contentsWithoutGlobalPcap = do
    --mapM_ print $ runGet getData contentsWithoutGlobalPcap
    mapM_ print $ getData contentsWithoutGlobalPcap

t :: (CL.ByteString -> IO ()) -> IO ()
t testf = do
    let file = "/home/ilya/Downloads/mdf-kospi200.20110216-0.pcap"
    contents <- BL.readFile file
    let contentsWithoutGlobalPcap = BL.drop 24 contents
    testf contentsWithoutGlobalPcap



reorder = undefined

rP contents = getData contentsWithoutGlobalPcap
    where contentsWithoutGlobalPcap = BL.drop 24 contents

helpM :: String
helpM = 
    "Please call with:\n"++
    indent ++ myName ++ " {file}\n"++
    "Alternatively, if you want to reorder records, call with:\n"++
    indent ++ myName ++ " -r {file}"
    where myName = "pcapKospi200"
          indent = "\t"

main :: IO ()
main = do
    let printL = mapM_ print
    args <- getArgs
    case args of
      (f:[])    -> do
          c <- BL.readFile f
          printL $ rP c
      (f:p:_)   -> do
          c <- BL.readFile f
          if p == "-r"
             then printL $ reorder $ rP c
             else printL $ rP c
      otherwise -> putStrLn helpM
