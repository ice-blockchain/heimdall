/**
 * SPDX-License-Identifier: ice License 1.0
 */

//Blocks with receipt dataset
var bondingCurveContractAddress = '0xF411faBcE1A441E5655db72419Ba2B0b95ec9fCC'.toLowerCase();
var uniswapV3Factory = '0x58F98CED992B39414bB4bCE347bedfC6b15AA596'.toLowerCase();
var bondingTokenFactory = '0x26dae540C37aD4190156D45eC1ddB32243Fa33d0'.toLowerCase();

var contractAddressesList = "staging_v2026.02.10.1";
async function main(payload) {
    try {
        await qnLib.qnUpsertList(contractAddressesList, {
            add_items: [bondingCurveContractAddress, uniswapV3Factory, bondingTokenFactory],
        });
    } catch (e) {}
    if (!payload || !payload.data || payload.data.length === 0) {
        return {
            transactions: [],
            stream: payload && payload.metadata ? payload.metadata.stream_id : ''
        };
    }

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
                allLogs.push({
                    address: log.address,
                    topics: log.topics,
                    data: log.data,
                    logIndex: log.logIndex,
                    removed: log.removed
                });
                containsContractAddress = await qnLib.qnContainsListItem(contractAddressesList, log.address)
                if (containsContractAddress) {
                    hasRelevant = true;
                    // BondingTokenCreated
                    if (log.topics[0].toLowerCase() === '0xf20c12ede00469181597169f5cbe631d40edec9a2a45c2e46eba231a831126dd') {
                        newContractAddress = log.topics[1].toLowerCase();
                        if (newContractAddress.length > 42) { // trim leading zeroes
                            newContractAddress = "0x"+newContractAddress.slice(26);
                        }
                        await qnLib.qnAddListItem(contractAddressesList, newContractAddress)
                    }
                    // UniswapV3PoolCreated
                    if (log.topics[0].toLowerCase() === '0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118') {
                        token0Address = log.topics[1].toLowerCase();
                        token1Address = log.topics[2].toLowerCase();
                        if (token0Address.length > 42) { // trim leading zeroes
                            token0Address = "0x"+token0Address.slice(26);
                        }
                        if (token1Address.length > 42) { // trim leading zeroes
                            token1Address = "0x"+token1Address.slice(26);
                        }
                        token0IsBondingToken = await qnLib.qnContainsListItem(contractAddressesList, token0Address);
                        token1IsBondingToken = await qnLib.qnContainsListItem(contractAddressesList, token1Address);
                        if (token0IsBondingToken || token1IsBondingToken) {
                            poolAddress = "0x"+log.data.slice(64+26).toLowerCase();
                            await qnLib.qnAddListItem(contractAddressesList, poolAddress)
                        }
                    }
                }
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
