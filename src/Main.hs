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
--import qualified Data.ByteString.Lazy.Char8 as C
--import Data.Binary.Get (Get, runGet, getWord64le, getInt32be, getWord32le, getWord32be, getWord16be, getWord8)
import Data.Binary.Get
import Data.Word (Word64, Word32, Word16, Word8)
import Data.Int (Int32)
import Data.Char (ord)

{-
data PriceVol = PriceVol
    { price :: Word32
    , vol   :: Word64
    } deriving Show
-}

--lenEthHeader = 14
--lenIP4Header = 20
lenEthAndIP4 = 34

data PriceVol = PriceVol
    { price :: Double
    , vol   :: Double
    }
instance Show PriceVol where
    show x = (show $ vol x) ++ "@" ++ (show $ price x)

data DataLine = DataLine
    { packetTime :: Integer
    , acceptTime :: Integer
    , issueCode  :: String
    , bids       :: [PriceVol]
    , asks       :: [PriceVol]
    } deriving Show

--getQuotePacket
--getPriceVol = PriceVol <$> getWord32le <*> getWord64le
--getPriceVol = PriceVol <$> getWord32be <*> getWord64be
--getPriceVol = PriceVol <$> (getByteString 5) <*> (getByteString 7)
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

data HeaderPcapPacket = HeaderPcapPacket
    { tsSecPcap   :: Word32
    , tsUsecPcap  :: Word32
    , inclLenPcap :: Word32
    , origLenPcap :: Word32
    } deriving (Show)

data HeaderUDPpacket = HeaderUDPpacket
    { sourcePortUDP :: Word16
    , destPortUDP   :: Word16
    , totalLenUDP   :: Word16
    , chkSumUDP     :: Word16
    } deriving (Show)

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

idString = "B6034"
lenPack  = 215

breakerBString = BL.pack $ map (fromIntegral . ord) idString

searchSubtringPosition sub str = stmp 0 0 sub str
    where
        stmp 5 pos _ _                 = pos
        stmp n pos su st
            | st == BL.empty           = 0
            | BL.head su /= BL.head st = stmp 0 (pos+n+1) sub (BL.tail st)
            | otherwise                = stmp (n+1) pos (BL.tail su) (BL.tail st)

{-
searchBBS bs c
  | BL.take 5 c == bs = s
  | otherwise         = searchBBS bs (BL.tail c)
  where
      s = BL.dropWhile (/= fromIntegral (BL.head bs)) c
-}

data ContentQuotePacket = ContentQuotePacket
    { issueCodeC  :: String
    , bidsC       :: [PriceVol]
    , asksC       :: [PriceVol]
    , acceptTimeC :: String
    } deriving Show

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

getDataLine :: Get (Maybe DataLine)
getDataLine = do
    headerPcap <- getHeaderPcapPacket
    skip lenEthAndIP4
    headerUDP  <- getHeaderUDP
    let lenUDP = fromIntegral $ totalLenUDP headerUDP
    dataId     <- getLazyByteString 5
    -- read only packets we're looking for, skip otherwise
    if CL.unpack dataId == idString && lenUDP == lenPack
       then do
           contentP   <- getContentQuotePacket
           let dataL =
                   DataLine
                       { packetTime = 0
                       , acceptTime = 0
                       , issueCode  = issueCodeC contentP
                       , bids       = reverse (bidsC contentP)
                       , asks       = asksC contentP
                       }
           return (Just dataL)
       else do
           skip lenUDP
           return Nothing


{-
test4 c | lenC >= lenD = (dataL : test4 cnext)
        | otherwise    = []
-}

--getPriceVolAll :: Get [PriceVol]
--getPriceVolAll = mapM (\_ -> getPriceVol) [1..5]
{-
getData :: Get [Maybe DataLine]
getData = do
  empty <- isEmpty
  if empty
    then return []
    else do line  <- getDataLine
            lines <- getData
            return (line:lines)
-}

getData :: ByteString -> [DataLine]
getData c = gd (length c) c
    where
        

incrementalExample :: BL.ByteString -> [Maybe DataLine]
incrementalExample input0 = go decoder input0
  where
      decoder = runGetIncremental getData
      go :: Decoder Maybe DataLine -> BL.ByteString -> [Maybe DataLine]
      go (Done leftover _consumed trade) input
        = trade : go decoder (BL.chunk leftover input)
      go (Partial k) input
        = go (k . takeHeadChunk $ input) (dropHeadChunk input)
      go (Fail _leftover _consumed msg) _input
        = error msg

test4 contentsWithoutGlobalPcap = do
    mapM_ print $ runGet getData contentsWithoutGlobalPcap
{-
repeatPriceVol 0 qData = []
repeatPriceVol n qData = runGet getPriceVol qData : repeatPriceVol (n-1) (BL.drop 12 qData)
-}

test3 :: BL.ByteString -> IO ()
test3 c = do
    let weird = do
        headerPcap <- getHeaderPcapPacket
        skip lenEthAndIP4
        headerUDP  <- getHeaderUDP
        contentP   <- getContentQuotePacket
        return contentP
    print $ runGet weird c



test2 :: Integer -> BL.ByteString -> IO ()
test2 n contentsWithoutGlobalPcap = do
    if contentsWithoutGlobalPcap == BL.empty || n <= 0
       then return ()
       else do
           --print $ runGet getHeaderPcapGlobal contents
           let line = runGet getDataLine contentsWithoutGlobalPcap
           print line
           test2 (n-1) contentsWithoutGlobalPcap

test1 :: Integer -> BL.ByteString -> IO ()
test1 n contentsWithoutGlobalPcap = do
    if contentsWithoutGlobalPcap == BL.empty || n <= 0
       then return ()
       else do
           --print $ runGet getHeaderPcapGlobal contents

           --print $ BL.take 5 $ searchBBS breakerBString c

           let p = searchSubtringPosition breakerBString contentsWithoutGlobalPcap
           -- 16 pcap header, 8 udp header
           let contentsPcapUDPdata = BL.drop (p-16-8) contentsWithoutGlobalPcap
           let contentsUDPdata = BL.drop 16 contentsPcapUDPdata

           let headerPcap = runGet getHeaderPcapPacket contentsPcapUDPdata
           let headerUDP = runGet getHeaderUDP contentsUDPdata
           let contentData = BL.drop 8 contentsUDPdata

           let res = runGet getContentQuotePacket contentData

           print res
           print n
           print (BL.length contentData)
           print "    "

           test1 (n-1) (BL.drop 215 contentData)

main :: IO ()
main = do
    let file = "/home/ilya/Downloads/mdf-kospi200.20110216-0.pcap"
    contents <- BL.readFile file
    let contentsWithoutGlobalPcap = BL.drop 24 contents

    test4 contentsWithoutGlobalPcap
    --test3 contentsWithoutGlobalPcap

    --print $ parseLines contentsWithoutGlobalPcap
    --print $ repeatPriceVol 5 $ BL.drop 7 quoteData

    --print $ runGet getHeaderUDP (BL.drop (16+34) contentsWithoutGlobalPcap)
    --print $ filter ((==155) . (`quot` 100) . snd) $ map (\x -> (x, destPort $ runGet getHeaderUDP (BL.drop (24+16+x) contents))) [1..2000]

