// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"

	"github.com/pkg/errors"

	nftcontent "github.com/ice-blockchain/heimdall/nft-content"
	"github.com/ice-blockchain/heimdall/server"
)

func (s *service) setupNFTRoutes(r *server.Router) {
	r.GET("v1/nft-collection-metadata/:nftContentType/:contentAddress", server.RootHandler(s.GetNFTCollectionMetadata))
}

// GetNFTCollectionMetadata godoc
//
//	@Description	Get NFT collection metadata
//	@Tags			NFT
//	@Produce		json
//	@Param			Authorization	header		string						true	"Auth token"	default(Bearer <Add token here>)
//	@Param			nftContentType	path		string						true	"NFT content type"
//	@Param			contentAddress	path		string						true	"Content address"
//	@Success		200				{object}	any							"NFT collection metadata"
//	@Header			200				{string}	X-Nft-Collection-Name		"NFT collection name"
//	@Header			200				{string}	X-Nft-Collection-Address	"NFT collection address"
//	@Header			200				{string}	X-Nft-Collection-Created-By	"NFT collection creator address"
//	@Failure		400				{object}	server.ErrorResponse		"Invalid request format"
//	@Failure		404				{object}	server.ErrorResponse		"NFT collection metadata not found"
//	@Failure		500				{object}	server.ErrorResponse		"Internal server error"
//	@Failure		504				{object}	server.ErrorResponse		"if request times out"
//	@Router			/v1/nft-collection-metadata/{nftContentType}/{contentAddress} [GET]
func (s *service) GetNFTCollectionMetadata(
	ctx context.Context,
	req *server.Request[GetNFTCollectionMetadataRequest, any],
) (*server.Response[any], *server.ErrResponse[*server.ErrorResponse]) {
	if err := validateNFTCollectionMetadataReq(req.Data.NFTContentType, req.Data.ContentAddress); err != nil {
		return nil, server.BadRequest(err, invalidPropertiesErrorCode)
	}
	var resp any
	var metadata *nftcontent.NFTCollectionMetadata
	var err error
	switch nftcontent.NFTContentType(req.Data.NFTContentType) {
	case nftcontent.NFTContentTypeAccount:
		resp, metadata, err = s.nftContent.GetNFTCollectionMetadataAccount(ctx, req.Data.NFTContentType, req.Data.ContentAddress)
	default:
		resp, metadata, err = s.nftContent.GetNFTCollectionMetadataContent(ctx, req.Data.NFTContentType, req.Data.ContentAddress)
	}
	if err != nil {
		switch {
		case errors.Is(err, nftcontent.ErrNotFound):
			return nil, server.NotFound(err, notFound)
		default:
			return nil, server.Unexpected(err)
		}
	}
	response := server.OK(&resp)
	response.Headers = map[string]string{
		"X-NFT-Collection-Name":       metadata.NFTCollectionName,
		"X-NFT-Collection-Address":    metadata.NFTCollectionAddress,
		"X-NFT-Collection-Created-By": metadata.NFTCollectionCreatorAddress,
	}

	return response, nil
}

func validateNFTCollectionMetadataReq(nftContentType, contentAddress string) error {
	types := map[nftcontent.NFTContentType]bool{
		nftcontent.NFTContentTypeAccount: true,
		nftcontent.NFTContentTypePost:    true,
		nftcontent.NFTContentTypeArticle: true,
		nftcontent.NFTContentTypeVideo:   true,
		nftcontent.NFTContentTypeStory:   true,
	}
	if _, ok := types[nftcontent.NFTContentType(nftContentType)]; !ok {
		return errors.Errorf("invalid nft content type")
	}
	if contentAddress == "" {
		return errors.Errorf("content address is required")
	}

	return nil
}
