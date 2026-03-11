// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2"
)

func TestUpdateTrendingVolumes(t *testing.T) {
	t.Parallel()
	t.Run("updates tokens with volume and removes tokens without volume", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		err := ta.processedDataDB.FlushDB(ctx).Err()
		require.NoError(t, err)

		token1ContractAddr := "0xtoken1_contract"
		token1ExtAddr := "ext_token1"
		token2ContractAddr := "0xtoken2_contract"
		token2ExtAddr := "ext_token2"
		token3ContractAddr := "0xtoken3_contract"
		token3ExtAddr := "ext_token3"

		helperInsertTestToken(t, ctx, db, token1ContractAddr, token1ExtAddr, "TKN1", TokenTypePost, "creator1", "1000000000000000000000", 0, 0, 0, PlatformGroupXCom)
		helperInsertTestToken(t, ctx, db, token2ContractAddr, token2ExtAddr, "TKN2", TokenTypePost, "creator2", "1000000000000000000000", 0, 0, 0, PlatformGroupXCom)
		helperInsertTestToken(t, ctx, db, token3ContractAddr, token3ExtAddr, "TKN3", TokenTypeProfile, "creator3", "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

		now := time.Now()
		helperInsertTokenSwap(t, ctx, db, token1ContractAddr, token1ExtAddr, "0xuser1", "0xtx1", false, "1000000000000000000", "1000000000000000000", 1.5, now)
		helperInsertTokenSwap(t, ctx, db, token2ContractAddr, token2ExtAddr, "0xuser2", "0xtx2", true, "2000000000000000000", "2000000000000000000", 2.0, now)

		_, err = storage.Exec(ctx, db, "REFRESH MATERIALIZED VIEW token_volumes_24h")
		require.NoError(t, err)

		err = ta.processedDataDB.ZAdd(ctx, globalTrendingSetKey, redis.Z{
			Score:  100.0,
			Member: token3ExtAddr,
		}).Err()
		require.NoError(t, err)

		require.NoError(t, ta.updateTrendingVolumes(ctx))

		members, err := ta.processedDataDB.ZRevRangeWithScores(ctx, globalTrendingSetKey, 0, -1).Result()
		require.NoError(t, err)
		require.Equal(t, 2, len(members), "should have 2 tokens with volume")

		foundToken1 := false
		foundToken2 := false
		for _, m := range members {
			if m.Member.(string) == token1ExtAddr {
				foundToken1 = true
			}
			if m.Member.(string) == token2ExtAddr {
				foundToken2 = true
			}
		}
		require.True(t, foundToken1, "token1 should be in trending set")
		require.True(t, foundToken2, "token2 should be in trending set")

		score, err := ta.processedDataDB.ZScore(ctx, globalTrendingSetKey, token3ExtAddr).Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err, "token3 should be removed from trending set")
		require.Equal(t, float64(0), score)
	})

	t.Run("adds xcom tokens to xcom trending set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		tokenContractAddr := "0xxcom_token_contract"
		tokenExtAddr := "ext_xcom_token"

		helperInsertTestToken(t, ctx, db, tokenContractAddr, tokenExtAddr, "XTKN", TokenTypePost, "creator_xcom", "1000000000000000000000", 0, 0, 0, PlatformGroupXCom)

		now := time.Now()
		helperInsertTokenSwap(t, ctx, db, tokenContractAddr, tokenExtAddr, "0xuserxcom", "0xxcomtx", false, "5000000000000000000", "5000000000000000000", 3.0, now)

		_, err := storage.Exec(ctx, db, "REFRESH MATERIALIZED VIEW token_volumes_24h")
		require.NoError(t, err)

		err = ta.updateTrendingVolumes(ctx)
		require.NoError(t, err)

		xcomScore, err := ta.processedDataDB.ZScore(ctx, globalTrendingXcomSetKey, tokenExtAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 1.5e+19, xcomScore, 1e12, "xcom token should have volume in wei*price_usd")

		globalScore, err := ta.processedDataDB.ZScore(ctx, globalTrendingSetKey, tokenExtAddr).Result()
		require.NoError(t, err)
		require.InDelta(t, 1.5e+19, globalScore, 1e12, "xcom token should also be in global trending set")
	})

	t.Run("adds content type tokens to anyPost set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		postContractAddr := "0xpost_token_contract"
		postExtAddr := "ext_post_token"
		videoContractAddr := "0xvideo_token_contract"
		videoExtAddr := "ext_video_token"

		helperInsertTestToken(t, ctx, db, postContractAddr, postExtAddr, "POST", TokenTypePost, "creator_post", "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)
		helperInsertTestToken(t, ctx, db, videoContractAddr, videoExtAddr, "VIDEO", TokenTypeVideo, "creator_video", "1000000000000000000000", 0, 0, 0, PlatformGroupIonConnect)

		now := time.Now()
		helperInsertTokenSwap(t, ctx, db, postContractAddr, postExtAddr, "0xuserpost", "0xposttx", false, "1000000000000000000", "1000000000000000000", 1.0, now)
		helperInsertTokenSwap(t, ctx, db, videoContractAddr, videoExtAddr, "0xuservideo", "0xvideotx", false, "2000000000000000000", "2000000000000000000", 2.0, now)

		_, err := storage.Exec(ctx, db, "REFRESH MATERIALIZED VIEW token_volumes_24h")
		require.NoError(t, err)

		err = ta.updateTrendingVolumes(ctx)
		require.NoError(t, err)

		anyPostMembers, err := ta.processedDataDB.ZRevRangeWithScores(ctx, globalTrendingAnyPostSetKey, 0, -1).Result()
		require.NoError(t, err)
		require.Equal(t, 2, len(anyPostMembers), "anyPost set should contain post and video tokens")

		foundPost := false
		foundVideo := false
		for _, m := range anyPostMembers {
			if m.Member.(string) == postExtAddr {
				foundPost = true
			}
			if m.Member.(string) == videoExtAddr {
				foundVideo = true
			}
		}
		require.True(t, foundPost, "post token should be in anyPost set")
		require.True(t, foundVideo, "video token should be in anyPost set")
	})

	t.Run("handles empty volumes gracefully", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		_, err := storage.Exec(ctx, db, "REFRESH MATERIALIZED VIEW token_volumes_24h")
		require.NoError(t, err)

		err = ta.updateTrendingVolumes(ctx)
		require.NoError(t, err)

		count, err := ta.processedDataDB.ZCard(ctx, globalTrendingSetKey).Result()
		require.NoError(t, err)
		require.Equal(t, int64(0), count)
	})
}

func TestGetAllTrendingSetKeys(t *testing.T) {
	t.Parallel()
	db, release := helperCreateDB(t)
	defer release()

	ta := helperNewForTest(t, db, WithoutQuestDB())

	keys := ta.getAllTrendingSetKeys()

	require.Equal(t, 10, len(keys), "should have global, xcom, xcom_combined, anyPost, onlineplus_creator, onlineplus_content, and 4 token type keys")

	require.Contains(t, keys, globalTrendingSetKey)
	require.Contains(t, keys, globalTrendingXcomSetKey)
	require.Contains(t, keys, globalTrendingXcomCombinedSetKey)
	require.Contains(t, keys, globalTrendingAnyPostSetKey)
	require.Contains(t, keys, globalTrendingOnlinePlusCreatorSetKey)
	require.Contains(t, keys, globalTrendingOnlinePlusContentSetKey)
	require.Contains(t, keys, getTrendingSetKeyByType(TokenTypeProfile))
	require.Contains(t, keys, getTrendingSetKeyByType(TokenTypePost))
	require.Contains(t, keys, getTrendingSetKeyByType(TokenTypeVideo))
	require.Contains(t, keys, getTrendingSetKeyByType(TokenTypeArticle))
}

func TestAddTokenToTrendingSets(t *testing.T) {
	t.Parallel()
	t.Run("adds xcom token to xcom set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupXCom
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken",
			Volume24h:       100.5,
			ExternalAddress: "ext_token",
			TokenType:       TokenTypePost,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		globalScore, err := ta.processedDataDB.ZScore(ctx, globalTrendingSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, globalScore)

		xcomScore, err := ta.processedDataDB.ZScore(ctx, globalTrendingXcomSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, xcomScore)
	})

	t.Run("adds ionconnect post token to type-specific and anyPost sets", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupIonConnect
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken2",
			Volume24h:       200.5,
			ExternalAddress: "ext_token2",
			TokenType:       TokenTypePost,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		globalScore, err := ta.processedDataDB.ZScore(ctx, globalTrendingSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, globalScore)

		typeKey := getTrendingSetKeyByType(TokenTypePost)
		typeScore, err := ta.processedDataDB.ZScore(ctx, typeKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, typeScore)

		anyPostScore, err := ta.processedDataDB.ZScore(ctx, globalTrendingAnyPostSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, anyPostScore)
	})

	t.Run("adds profile token to type-specific set only", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupIonConnect
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken3",
			Volume24h:       300.5,
			ExternalAddress: "ext_token3",
			TokenType:       TokenTypeProfile,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		globalScore, err := ta.processedDataDB.ZScore(ctx, globalTrendingSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, globalScore)

		typeKey := getTrendingSetKeyByType(TokenTypeProfile)
		typeScore, err := ta.processedDataDB.ZScore(ctx, typeKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, typeScore)

		_, err = ta.processedDataDB.ZScore(ctx, globalTrendingAnyPostSetKey, vol.ExternalAddress).Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err)
	})

	t.Run("xcom_token_populates_combined_set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupXCom
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken_xcomb",
			Volume24h:       400.0,
			ExternalAddress: "ext_xcom_combined",
			TokenType:       TokenTypeProfile,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		combinedScore, err := ta.processedDataDB.ZScore(ctx, globalTrendingXcomCombinedSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, combinedScore)
	})

	t.Run("ionconnect_profile_populates_combined_set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupIonConnect
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken_ion_prof",
			Volume24h:       500.0,
			ExternalAddress: "ext_ion_profile_combined",
			TokenType:       TokenTypeProfile,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		combinedScore, err := ta.processedDataDB.ZScore(ctx, globalTrendingXcomCombinedSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, combinedScore)
	})

	t.Run("ionconnect_post_does_not_populate_combined_set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupIonConnect
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken_ion_post",
			Volume24h:       600.0,
			ExternalAddress: "ext_ion_post_not_combined",
			TokenType:       TokenTypePost,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		_, err = ta.processedDataDB.ZScore(ctx, globalTrendingXcomCombinedSetKey, vol.ExternalAddress).Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err, "post token should not be in combined set")
	})

	t.Run("ionconnect_profile_populates_onlineplus_creator_set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupIonConnect
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken_opc_prof",
			Volume24h:       700.0,
			ExternalAddress: "ext_opc_profile",
			TokenType:       TokenTypeProfile,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalTrendingOnlinePlusCreatorSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, score)

		_, err = ta.processedDataDB.ZScore(ctx, globalTrendingOnlinePlusContentSetKey, vol.ExternalAddress).Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err, "profile should not be in onlineplus_content set")
	})

	t.Run("ionconnect_post_populates_onlineplus_content_set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupIonConnect
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken_opc_post",
			Volume24h:       800.0,
			ExternalAddress: "ext_opc_post",
			TokenType:       TokenTypePost,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalTrendingOnlinePlusContentSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, score)

		_, err = ta.processedDataDB.ZScore(ctx, globalTrendingOnlinePlusCreatorSetKey, vol.ExternalAddress).Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err, "post should not be in onlineplus_creator set")
	})

	t.Run("ionconnect_video_populates_onlineplus_content_set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupIonConnect
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken_opc_video",
			Volume24h:       900.0,
			ExternalAddress: "ext_opc_video",
			TokenType:       TokenTypeVideo,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalTrendingOnlinePlusContentSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, score)

		_, err = ta.processedDataDB.ZScore(ctx, globalTrendingOnlinePlusCreatorSetKey, vol.ExternalAddress).Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err, "video should not be in onlineplus_creator set")
	})

	t.Run("xcom_token_does_not_populate_onlineplus_sets", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupXCom
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken_xcom_opc",
			Volume24h:       1000.0,
			ExternalAddress: "ext_xcom_not_opc",
			TokenType:       TokenTypeProfile,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		_, err = ta.processedDataDB.ZScore(ctx, globalTrendingOnlinePlusCreatorSetKey, vol.ExternalAddress).Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err, "xcom profile should not be in onlineplus_creator set")

		_, err = ta.processedDataDB.ZScore(ctx, globalTrendingOnlinePlusContentSetKey, vol.ExternalAddress).Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err, "xcom profile should not be in onlineplus_content set")
	})

	t.Run("ionconnect_article_populates_onlineplus_content_set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		pipe := ta.processedDataDB.TxPipeline()
		platform := PlatformGroupIonConnect
		vol := &volumeWithType{
			Platform:        &platform,
			TokenAddress:    "0xtoken_opc_article",
			Volume24h:       1100.0,
			ExternalAddress: "ext_opc_article",
			TokenType:       TokenTypeArticle,
		}

		ta.addTokenToTrendingSets(ctx, pipe, vol)
		_, err := pipe.Exec(ctx)
		require.NoError(t, err)

		score, err := ta.processedDataDB.ZScore(ctx, globalTrendingOnlinePlusContentSetKey, vol.ExternalAddress).Result()
		require.NoError(t, err)
		require.Equal(t, vol.Volume24h, score)

		_, err = ta.processedDataDB.ZScore(ctx, globalTrendingOnlinePlusCreatorSetKey, vol.ExternalAddress).Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err, "article should not be in onlineplus_creator set")
	})
}

func TestRemoveNonExistentTokens(t *testing.T) {
	t.Parallel()
	t.Run("removes tokens not in temp set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		setKey := "test:trending:set"
		tempSetKey := "test:temp:set"

		err := ta.processedDataDB.ZAdd(ctx, setKey, redis.Z{Score: 100, Member: "token1"}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, setKey, redis.Z{Score: 200, Member: "token2"}).Err()
		require.NoError(t, err)
		err = ta.processedDataDB.ZAdd(ctx, setKey, redis.Z{Score: 300, Member: "token3"}).Err()
		require.NoError(t, err)

		err = ta.processedDataDB.SAdd(ctx, tempSetKey, "token1", "token3").Err()
		require.NoError(t, err)

		members := []string{"token1", "100", "token2", "200", "token3", "300"}

		removed, err := ta.removeNonExistentTokens(ctx, setKey, tempSetKey, members)
		require.NoError(t, err)
		require.Equal(t, 1, removed, "should remove 1 token (token2)")

		_, err = ta.processedDataDB.ZScore(ctx, setKey, "token2").Result()
		require.Error(t, err)
		require.Equal(t, redis.Nil, err)

		score1, err := ta.processedDataDB.ZScore(ctx, setKey, "token1").Result()
		require.NoError(t, err)
		require.Equal(t, float64(100), score1)

		score3, err := ta.processedDataDB.ZScore(ctx, setKey, "token3").Result()
		require.NoError(t, err)
		require.Equal(t, float64(300), score3)

		_ = ta.processedDataDB.Del(ctx, setKey, tempSetKey).Err()
	})

	t.Run("removes nothing when all tokens exist in temp set", func(t *testing.T) {
		db, release := helperCreateDB(t)
		defer release()

		ta := helperNewForTest(t, db, WithoutQuestDB())
		ctx := context.Background()

		_ = ta.processedDataDB.FlushDB(ctx).Err()

		setKey := "test:trending:set2"
		tempSetKey := "test:temp:set2"

		err := ta.processedDataDB.ZAdd(ctx, setKey, redis.Z{Score: 100, Member: "token1"}).Err()
		require.NoError(t, err)

		err = ta.processedDataDB.SAdd(ctx, tempSetKey, "token1").Err()
		require.NoError(t, err)

		members := []string{"token1", "100"}

		removed, err := ta.removeNonExistentTokens(ctx, setKey, tempSetKey, members)
		require.NoError(t, err)
		require.Equal(t, 0, removed, "should remove 0 tokens")

		score, err := ta.processedDataDB.ZScore(ctx, setKey, "token1").Result()
		require.NoError(t, err)
		require.Equal(t, float64(100), score)

		_ = ta.processedDataDB.Del(ctx, setKey, tempSetKey).Err()
	})
}
