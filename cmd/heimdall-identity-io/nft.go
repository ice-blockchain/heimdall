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
	r.GET("v1/nft-collection-metadata/:nftContentType/:contentAddress/html-preview", server.RootHandler(s.GetNFTCollectionMetadataHtmlPreview))
}

// GetNFTCollectionMetadata godoc
//
//	@Description	Get NFT collection metadata
//	@Tags			NFT
//	@Produce		json
//	@Param			nftContentType	path		string							true	"NFT content type"	Enums(user, account, post, article, video, story)
//	@Param			contentAddress	path		string							true	"Content address"
//	@Success		200				{object}	nftcontent.NFTResponse			"NFT collection metadata"
//	@Header			200				{string}	X-Nft-Collection-Name			"NFT collection name"
//	@Header			200				{string}	X-Nft-Collection-Address		"NFT collection address"
//	@Header			200				{string}	X-Nft-Collection-Created-By		"NFT collection creator address"
//	@Header			200				{string}	Access-Control-Allow-Origin		"CORS: Allowed origins"
//	@Header			200				{string}	Access-Control-Allow-Methods	"CORS: Allowed HTTP methods"
//	@Header			200				{string}	Access-Control-Allow-Headers	"CORS: Allowed request headers"
//	@Header			200				{string}	Access-Control-Expose-Headers	"CORS: Headers exposed to client"
//	@Failure		400				{object}	server.ErrorResponse			"Invalid request format"
//	@Failure		404				{object}	server.ErrorResponse			"NFT collection metadata not found"
//	@Failure		500				{object}	server.ErrorResponse			"Internal server error"
//	@Failure		504				{object}	server.ErrorResponse			"if request times out"
//	@Router			/v1/nft-collection-metadata/{nftContentType}/{contentAddress} [GET]
func (s *service) GetNFTCollectionMetadata(
	ctx context.Context,
	req *server.Request[GetNFTCollectionMetadataRequest, *nftcontent.NFTResponse],
) (*server.Response[*nftcontent.NFTResponse], *server.ErrResponse[*server.ErrorResponse]) {
	var (
		err      error
		resp     *nftcontent.NFTResponse
		metadata *nftcontent.NFTCollectionMetadata
	)
	if req.Data.NFTContentType == "user" {
		resp, metadata, err = s.nftContent.GetNFTCollectionMetadata(ctx, req.Data.ContentAddress)
	} else {
		resp, metadata, err = s.nftContent.GetNFTCollectionItemMetadata(ctx, req.Data.NFTContentType, req.Data.ContentAddress)
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
		"X-NFT-Collection-Name":         metadata.NFTCollectionName,
		"X-NFT-Collection-Address":      metadata.NFTCollectionAddress,
		"X-NFT-Collection-Created-By":   metadata.NFTCollectionCreatorAddress,
		"Access-Control-Allow-Origin":   "*",
		"Access-Control-Allow-Methods":  "GET, OPTIONS",
		"Access-Control-Allow-Headers":  "Content-Type",
		"Access-Control-Expose-Headers": "X-NFT-Collection-Name, X-NFT-Collection-Address, X-NFT-Collection-Created-By",
	}

	return response, nil
}

// GetNFTCollectionMetadataHtmlPreview
//
//	@Summary		Get NFT collection metadata HTML preview
//	@Description	Get NFT collection metadata as HTML preview
//	@Tags			NFT
//	@Produce		html
//	@Param			nftContentType	path		string							true	"NFT content type"	Enums(account, post, article, video, story)
//	@Param			contentAddress	path		string							true	"Content address"
//	@Success		200				{string}	string							"HTML preview of NFT collection metadata"
//	@Header			200				{string}	Access-Control-Allow-Origin		"CORS: Allowed origins"
//	@Header			200				{string}	Access-Control-Allow-Methods	"CORS: Allowed HTTP methods"
//	@Header			200				{string}	Access-Control-Allow-Headers	"CORS: Allowed request headers"
//	@Failure		400				{object}	server.ErrorResponse			"Invalid request format"
//	@Failure		422				{object}	server.ErrorResponse			"Invalid request format"
//	@Failure		500				{object}	server.ErrorResponse			"Internal server error"
//	@Failure		504				{object}	server.ErrorResponse			"if request times out"
//	@Router			/v1/nft-collection-metadata/{nftContentType}/{contentAddress}/html-preview [GET]
func (s *service) GetNFTCollectionMetadataHtmlPreview(
	ctx context.Context,
	req *server.Request[GetNFTCollectionMetadataHtmlPreviewRequest, string],
) (*server.Response[string], *server.ErrResponse[*server.ErrorResponse]) {
	response := server.Raw("text/html; charset=utf-8", []byte(`
		<!DOCTYPE html>
		<html lang="en">
			<head>
			<meta name="description" content="HTML preview of NFT collection metadata" />
			<meta charset="utf-8">
			<title>NFT Collection Metadata</title>
			</head>
			<body></body>
		</html>
	`))
	response.Headers = map[string]string{
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "GET, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type",
	}

	return response, nil
}
