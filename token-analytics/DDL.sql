-- SPDX-License-Identifier: ice License 1.0

CREATE TABLE IF NOT EXISTS raw_tx_data
(
    address             TEXT NOT NULL,
    topics              TEXT[],
    data                TEXT,
    blockNumber         TEXT NOT NULL,
    transactionHash     TEXT NOT NULL,
    transactionIndex    TEXT NOT NULL,
    blockHash           TEXT NOT NULL,
    blockTimestamp      TEXT NOT NULL,
    logIndex            TEXT NOT NULL,
    removed             BOOLEAN NOT NULL,
    primary key (transactionHash, logIndex)
);

---          "address": "0xb05f36c9dffa76f0af639385ef44d5560e0160c1",
--          "topics": [ // topic 0 should point to event (hex)
--             "0x034dd13d657aeb14f8dec7291c4a8ddb3b20d40cf2412714e72f97f19c735609",
--             "0x000000000000000000000000000000000000000000000000000000000000477d",
--             "0x00000000000000000000000006054cfa0b56f350687b72d8944f7c235d4a0a43"
--           ],
--           "data": "0x",
--           "blockNumber": "0x91f3eb",
--           "transactionHash": "0xf2f810e59c7de7e2e92161ca2f756be7619a301c89db526aec29c2b135337d51",
--           "transactionIndex": "0x2",
--           "blockHash": "0xc6f373a8870c5634acf696e9158f9f02e18b4bf9bf6c8ba5b19cc1ac2c22aeb3",
--           "blockTimestamp": "0x690b1e94",
--           "logIndex": "0x1",
--           "removed": false