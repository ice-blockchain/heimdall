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
    data[0].block.transactions = data[0].block.transactions.filter(tx => txs[tx.hash] === true)
    return {
        'logs': filtered.map(receipt => receipt.logs).flat(2),
        'block': data[0].block,
        'stream': metadata.stream_id
    };
}