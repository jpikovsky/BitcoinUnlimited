// Copyright (c) 2016-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOBTAIL_H
#define BITCOIN_BOBTAIL_H

#include "bloom.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "protocol.h"
#include "serialize.h"
#include "stat.h"
#include "sync.h"
#include "uint256.h"
#include <atomic>
#include <vector>

class CDataStream;
class CNode;

class CBobtail
{
public:
    CBlockHeader header;
    std::vector<uint256> vTxHashes; // List of all transactions id's in the block
    std::vector<CTransaction> vMissingTx; // vector of transactions that did not match the bloom filter

public:
    CBobtail(const CBlock &block, CBloomFilter &filter);
    CBobtail() {}
    /**
     * Handle an incoming thin block.  The block is fully validated, and if any transactions are missing, we fall
     * back to requesting a full block.
     * @param[in] vRecv        The raw binary message
     * @param[in] pFrom        The node the message was from
     * @return True if handling succeeded
     */
    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(header);
        READWRITE(vTxHashes);
        READWRITE(vMissingTx);
    }

    CInv GetInv() { return CInv(MSG_BLOCK, header.GetHash()); }
    bool process(CNode *pfrom, int nSizeBobtail);
};

class CXBobtail
{
public:
    CBlockHeader header;
    std::vector<uint64_t> vTxHashes; // List of all transactions id's in the block
    std::vector<CTransaction> vMissingTx; // vector of transactions that did not match the bloom filter
    bool collision;

public:
    CXBobtail(const CBlock &block, CBloomFilter *filter); // Use the filter to determine which txns the client has
    CXBobtail(const CBlock &block); // Assume client has all of the transactions (except coinbase)
    CXBobtail() {}
    /**
     * Handle an incoming Xthin or Xpedited block
     * Once the block is validated apart from the Merkle root, forward the Xpedited block with a hop count of nHops.
     * @param[in]  vRecv        The raw binary message
     * @param[in] pFrom        The node the message was from
     * @param[in]  strCommand   The message kind
     * @param[in]  nHops        On the wire, an Xpedited block has a hop count of zero the first time it is sent, and
     *                          the hop count is incremented each time it is forwarded.  nHops is zero for an incoming
     *                          Xthin block, and for an incoming Xpedited block its hop count + 1.
     * @return True if handling succeeded
     */
    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom, std::string strCommand, unsigned nHops);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(header);
        READWRITE(vTxHashes);
        READWRITE(vMissingTx);
    }
    CInv GetInv() { return CInv(MSG_BLOCK, header.GetHash()); }
    bool process(CNode *pfrom, int nSizeThinbBlock, std::string strCommand);
    bool CheckBlockHeader(const CBlockHeader &block, CValidationState &state);
};

// This class is used to respond to requests for missing transactions after sending an XThin block.
// It is filled with the requested transactions in order.
class CXBobtailTx
{
public:
    /** Public only for unit testing */
    uint256 blockhash;
    std::vector<CTransaction> vMissingTx; // map of missing transactions

public:
    CXBobtailTx(uint256 blockHash, std::vector<CTransaction> &vTx);
    CXBobtailTx() {}
    /**
     * Handle receiving a list of missing xthin block transactions from a prior request
     * @param[in] vRecv        The raw binary message
     * @param[in] pFrom        The node the message was from
     * @return True if handling succeeded
     */
    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(blockhash);
        READWRITE(vMissingTx);
    }
};

// This class is used for requests for still missing transactions after processing a "Bobtail" message.
// This class uses a 64bit hash as opposed to the normal 256bit hash.  The target is expected to reply with
// a serialized CXBobtailTx response message.
class CXRequestBobtailTx
{
public:
    /** Public only for unit testing */
    uint256 blockhash;
    std::set<uint64_t> setCheapHashesToRequest; // map of missing transactions

public:
    CXRequestBobtailTx(uint256 blockHash, std::set<uint64_t> &setHashesToRequest);
    CXRequestBobtailTx() {}
    /**
     * Handle an incoming request for missing xthin block transactions
     * @param[in] vRecv        The raw binary message
     * @param[in] pFrom        The node the message was from
     * @return True if handling succeeded
     */
    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom);
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(blockhash);
        READWRITE(setCheapHashesToRequest);
    }
};

// This class stores statistics for thin block derived protocols.
class CBobtailData
{
private:
    /* The sum total of all bytes for Bobtails currently in process of being reconstructed */
    std::atomic<uint64_t> nBobtailBytes{0};

    CCriticalSection cs_mapBobtailTimer; // locks mapBobtailTimer
    std::map<uint256, uint64_t> mapBobtailTimer;

    CCriticalSection cs_Bobtailstats; // locks everything below this point

    CStatHistory<uint64_t> nOriginalSize;
    CStatHistory<uint64_t> nThinSize;
    CStatHistory<uint64_t> nBlocks;
    CStatHistory<uint64_t> nMempoolLimiterBytesSaved;
    CStatHistory<uint64_t> nTotalBloomFilterBytes;
    std::map<int64_t, std::pair<uint64_t, uint64_t> > mapBobtailsInBound;
    std::map<int64_t, std::pair<uint64_t, uint64_t> > mapBobtailsOutBound;
    std::map<int64_t, uint64_t> mapBloomFiltersOutBound;
    std::map<int64_t, uint64_t> mapBloomFiltersInBound;
    std::map<int64_t, double> mapBobtailResponseTime;
    std::map<int64_t, double> mapBobtailValidationTime;
    std::map<int64_t, int> mapBobtailsInBoundReRequestedTx;

    /**
        Add new entry to statistics array; also removes old timestamps
        from statistics array using expireStats() below.
        @param [statsMap] a statistics array
        @param [value] the value to insert for the current time
     */
    template <class T>
    void updateStats(std::map<int64_t, T> &statsMap, T value);

    /**
       Expire old statistics in given array (currently after one day).
       Uses getTimeForStats() virtual method for timing. */
    template <class T>
    void expireStats(std::map<int64_t, T> &statsMap);

    /**
      Calculate average of long long values in given map. Return 0 for no entries.
      Expires values before calculation. */
    double average(std::map<int64_t, uint64_t> &map);

protected:
    //! Virtual method so it can be overridden for better unit testing
    virtual int64_t getTimeForStats() { return GetTimeMillis(); }
public:
    void UpdateInBound(uint64_t nBobtailSize, uint64_t nOriginalBlockSize);
    void UpdateOutBound(uint64_t nBobtailSize, uint64_t nOriginalBlockSize);
    void UpdateOutBoundBloomFilter(uint64_t nBloomFilterSize);
    void UpdateInBoundBloomFilter(uint64_t nBloomFilterSize);
    void UpdateResponseTime(double nResponseTime);
    void UpdateValidationTime(double nValidationTime);
    void UpdateInBoundReRequestedTx(int nReRequestedTx);
    void UpdateMempoolLimiterBytesSaved(unsigned int nBytesSaved);
    std::string ToString();
    std::string InBoundPercentToString();
    std::string OutBoundPercentToString();
    std::string InBoundBloomFiltersToString();
    std::string OutBoundBloomFiltersToString();
    std::string ResponseTimeToString();
    std::string ValidationTimeToString();
    std::string ReRequestedTxToString();
    std::string MempoolLimiterBytesSavedToString();

    bool CheckBobtailTimer(uint256 hash);
    void ClearBobtailTimer(uint256 hash);

    void ClearBobtailData(CNode *pfrom);
    void ClearBobtailData(CNode *pfrom, uint256 hash);

    uint64_t AddBobtailBytes(uint64_t, CNode *pfrom);
    void DeleteBobtailBytes(uint64_t, CNode *pfrom);
    void ResetBobtailBytes();
    uint64_t GetBobtailBytes();
};
extern CBobtailData thindata; // Singleton class


bool HaveConnectBobtailNodes();
bool HaveBobtailNodes();
bool IsBobtailsEnabled();
bool CanBobtailBeDownloaded(CNode *pto);
void ConnectToBobtailNodes();
void CheckNodeSupportForBobtails();
bool ClearLargestBobtailAndDisconnect(CNode *pfrom);
void ClearBobtailInFlight(CNode *pfrom, uint256 hash);
void AddBobtailInFlight(CNode *pfrom, uint256 hash);
void SendXBobtail(CBlock &block, CNode *pfrom, const CInv &inv);
bool IsBobtailValid(CNode *pfrom, const std::vector<CTransaction> &vMissingTx, const CBlockHeader &header);
void BuildSeededBloomFilter(CBloomFilter &memPoolFilter,
    std::vector<uint256> &vOrphanHashes,
    uint256 hash,
    CNode *pfrom,
    bool fDeterministic = false);

// Xpress Validation: begin
// Transactions that have already been accepted into the memory pool do not need to be
// re-verified and can avoid having to do a second and expensive CheckInputs() when
// processing a new block.  (Protected by cs_xval)
extern std::set<uint256> setPreVerifiedTxHash;

// Orphans that are added to the Bobtail must be verifed since they have never been
// accepted into the memory pool.  (Protected by cs_xval)
extern std::set<uint256> setUnVerifiedOrphanTxHash;

extern CCriticalSection cs_xval;
// Xpress Validation: end

#endif // BITCOIN_Bobtail_H
