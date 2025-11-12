/**
 * SPDX-License-Identifier: ice License 1.0
 */

//Blocks with receipt dataset

function main(payload) {
    const {
        data,
        metadata,
    } = payload;
    txs = {}
    filtered = data[0].receipts.filter(function(item) {
        logs = item.logs.filter(function(log) {
            // Contract addr
            contains = log.address.toLowerCase() === '{{.ContractAddress}}'.toLowerCase()
            if (contains) {
                txs[log.transactionHash] = true
            }
            return contains
        })

        return logs.length > 0
    })
    const relevantTransactions = data[0].block.transactions.filter(tx => txs[tx.hash] === true);
    
    relevantTransactions.forEach(tx => {
        tx.blockHash = data[0].block.hash;
        tx.blockTimestamp = data[0].block.timestamp;
    });
    
    return {
        'transactions': relevantTransactions,
        'logs': filtered.map(receipt => receipt.logs).flat(2),
        'stream': metadata.stream_id
    };
}