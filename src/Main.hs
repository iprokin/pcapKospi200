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
--import Data.Binary.Get (Get, runGet, getWord64le, getInt32be, getWord32le, getWord32be, getWord16be, getWord8)
import Data.Binary.Get
import Data.Word (Word64, Word32, Word16, Word8)
import Data.Int (Int32)
import Data.Char (ord)

data Quote = Quote
    { issueCode    :: String
    }

{-
data PriceVol = PriceVol
    { price :: Word32
    , vol   :: Word64
    } deriving Show
-}


data PriceVol = PriceVol
    { price :: Float
    , vol   :: Double
    } deriving Show

--getQuotePacket
--getPriceVol = PriceVol <$> getWord32le <*> getWord64le
--getPriceVol = PriceVol <$> getWord32be <*> getWord64be
getPriceVol = PriceVol <$> getFloatbe <*> getDoublebe

data HeaderPcapGlobal = HeaderPcapGlobal
    { magicNumber  :: Word32
    , versionMajor :: Word16
    , versionMinor :: Word16
    , thisZone     :: Int32
    , sigFigs      :: Word32
    , snapLen      :: Word32
    , network      :: Word32
    } deriving (Show)

data HeaderPcapPacket = HeaderPcapPacket
    { tsSec   :: Word32
    , tsUsec  :: Word32
    , inclLen :: Word32
    , origLen :: Word32
    } deriving (Show)

{-
data HeaderUDPpacket = HeaderUDPpacket
    { sourceIP   :: Word32
    , destIP     :: Word32
    , protocol   :: Word8
    , uLen       :: Word16
    , sourcePort :: Word16
    , destPort   :: Word16
    , len        :: Word16
    , chkSum     :: Word16
    } deriving (Show)
-}

data HeaderUDPpacket = HeaderUDPpacket
    { sourcePort :: Word16
    , destPort   :: Word16
    , totalLen   :: Word16
    , chkSum     :: Word16
    } deriving (Show)

getHeaderPcapGlobal :: Get HeaderPcapGlobal
getHeaderPcapGlobal = do
    magicNumber  <- getWord32be
    versionMajor <- getWord16be
    versionMinor <- getWord16be
    thisZone     <- getInt32be
    sigFigs      <- getWord32be
    snapLen      <- getWord32be
    network      <- getWord32be
    return $ HeaderPcapGlobal
        { magicNumber  = magicNumber
        , versionMajor = versionMajor
        , versionMinor = versionMinor
        , thisZone     = thisZone
        , sigFigs      = sigFigs
        , snapLen      = snapLen
        , network      = network
        }

getHeaderPcapPacket :: Get HeaderPcapPacket
getHeaderPcapPacket = do
    tsSec   <- getWord32le
    tsUsec  <- getWord32be
    inclLen <- getWord32be
    origLen <- getWord32be
    return $ HeaderPcapPacket tsSec tsUsec inclLen origLen

getHeaderUDP :: Get HeaderUDPpacket
getHeaderUDP = do
    sourcePort <- getWord16be
    destPort   <- getWord16be
    totalLen   <- getWord16be
    chkSum     <- getWord16be
    return $ HeaderUDPpacket sourcePort destPort (totalLen-8) chkSum

{-
getHeaderUDP :: Get HeaderUDPpacket
getHeaderUDP = do
    sourceIP   <- getWord32be
    destIP     <- getWord32be
    _          <- getWord8
    protocol   <- getWord8
    uLen       <- getWord16be
    sourcePort <- getWord16be
    destPort   <- getWord16be
    len        <- getWord16be
    chkSum     <- getWord16be
    return $ HeaderUDPpacket
        { sourceIP   = sourceIP
        , destIP     = destIP
        , protocol   = protocol
        , uLen       = uLen
        , sourcePort = sourcePort
        , destPort   = destPort
        , len        = len
        , chkSum     = chkSum
        }
-}
getUDP c = BL.take (fromIntegral l) c
    where l = chkSum $ runGet getHeaderUDP c

breakerBString = BL.pack $ map (fromIntegral . ord) "B6034"

searchSubtringPosition sub str = stmp 0 0 sub str
    where
        stmp 5 pos _ _       = pos
        stmp n pos su st | st == BL.empty           = 0
                         | BL.head su /= BL.head st = stmp 0 (pos+n+1) sub (BL.tail st)
                         | otherwise                = stmp (n+1) pos (BL.tail su) (BL.tail st)

searchBBS bs c
  | BL.take 5 c == bs = s
  | otherwise         = searchBBS bs (BL.tail c)
  where
      s = BL.dropWhile (/= fromIntegral (BL.head bs)) c

repeatPriceVol 0 qData = []
repeatPriceVol n qData = runGet getPriceVol qData : repeatPriceVol (n-1) (BL.drop 12 qData)

main :: IO ()
main = do
    let file = "/home/ilya/Downloads/mdf-kospi200.20110216-0.pcap"
    contents <- BL.readFile file
    print $ runGet getHeaderPcapGlobal contents
    let contentsWithoutGlobalPcap = BL.drop 24 contents

    --print $ BL.take 5 $ searchBBS breakerBString c

    let p = searchSubtringPosition breakerBString contentsWithoutGlobalPcap
    -- 16 pcap header, 8 udp header
    let contentsPcapUDPdata = BL.drop (p-16-8) contentsWithoutGlobalPcap
    let contentsUDPdata = BL.drop 16 contentsPcapUDPdata

    let headerPcap = runGet getHeaderPcapPacket contentsPcapUDPdata
    let headerUDP = runGet getHeaderUDP contentsUDPdata
    let contentData = (BL.take (fromIntegral $ totalLen headerUDP) . BL.drop 8) contentsUDPdata

    print headerPcap
    print headerUDP
    print contentData

    print $ (BL.take 12 . BL.drop 5) contentData
    let quoteData = BL.drop 22 contentData
    print $ quoteData
    print $ runGet getPriceVol $ BL.take 12 $ BL.drop 7 quoteData
    --print $ repeatPriceVol 5 $ BL.drop 7 quoteData

    --print $ runGet getHeaderUDP (BL.drop (16+34) contentsWithoutGlobalPcap)
    --print $ filter ((flip elem [15572, 15515, 15516]). snd) $ map (\x -> (x, destPort $ runGet getHeaderUDP (BL.drop (24+16+x) contents))) [1..2000]

