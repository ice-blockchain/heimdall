/**
 * SPDX-License-Identifier: ice License 1.0
 */

//Blocks with receipt dataset

function main(payload) {
    if (!payload || !payload.data || payload.data.length === 0) {
        return {
            transactions: [],
            stream: payload && payload.metadata ? payload.metadata.stream_id : ''
        };
    }
    
    var contractAddress = '{{.ContractAddress}}'.toLowerCase();
    var allResults = [];
    
    for (var blockIdx = 0; blockIdx < payload.data.length; blockIdx++) {
        var blockData = payload.data[blockIdx];
        if (!blockData || !blockData.block || !blockData.receipts) continue;
        
        var txLogsMap = {};
        var txHasRelevantLogs = {};
        var block = blockData.block;
        var receipts = blockData.receipts;
        
        for (var i = 0; i < receipts.length; i++) {
            var receipt = receipts[i];
            if (!receipt.logs) continue;
            
            var hasRelevant = false;
            var allLogs = [];
            
            for (var j = 0; j < receipt.logs.length; j++) {
                var log = receipt.logs[j];
                if (log.address.toLowerCase() === contractAddress) {
                    hasRelevant = true;
                }
                allLogs.push({
                    address: log.address,
                    topics: log.topics,
                    data: log.data,
                    logIndex: log.logIndex,
                    removed: log.removed
                });
            }
            
            if (hasRelevant) {
                txLogsMap[receipt.transactionHash] = allLogs;
                txHasRelevantLogs[receipt.transactionHash] = true;
            }
        }
        
        var transactions = block.transactions || [];
        
        for (var k = 0; k < transactions.length; k++) {
            var tx = transactions[k];
            if (txHasRelevantLogs[tx.hash]) {
                var newTx = {};
                for (var key in tx) {
                    newTx[key] = tx[key];
                }
                newTx.blockHash = block.hash;
                newTx.blockNumber = block.number;
                newTx.blockTimestamp = block.timestamp;
                newTx.logs = txLogsMap[tx.hash];
                allResults.push(newTx);
            }
        }
    }
    
    return {
        transactions: allResults,
        stream: payload.metadata.stream_id
    };
}
