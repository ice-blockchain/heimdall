// SPDX-License-Identifier: ice License 1.0

package main

import (
	"context"
	"fmt"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts"
	"github.com/ice-blockchain/heimdall/server"
)

func (s *service) setupSocialProfileRoutes(r *server.Router) {
	r.GET("v1/users/verify-username-availability", server.RootHandler(s.VerifyUsernameAvailability))
	r.PATCH("v1/users/:userIdOrMasterKey/profiles/social", server.RootHandler(s.UpsertSocialProfile))
	r.GET("v1/user-social-profiles", server.RootHandler(s.SearchSocialProfiles))
}

// VerifyUsernameAvailability checks the availability of a username
//
//	@Description	Checks if the specified username is available
//	@Tags			SocialProfiles
//	@Accept			json
//	@Produce		json
//	@Param			Authorization	header		string					true	"Authorization token"
//	@Param			username		query		string					true	"Username to check"
//	@Success		200				{object}	nil						"Username is available"
//	@Failure		400				{object}	server.ErrorResponse	"Invalid username format"
//	@Failure		409				{object}	server.ErrorResponse	"Username already exists"
//	@Router			/v1/users/verify-username-availability [GET]
func (s *service) VerifyUsernameAvailability(
	ctx context.Context,
	req *server.Request[VerifyUsernameRequest, interface{}],
) (*server.Response[interface{}], *server.ErrResponse[*server.ErrorResponse]) {
	if err := s.accounts.VerifyUsernameAvailability(ctx, req.Data.Username); err != nil {
		switch {
		case errors.Is(err, accounts.ErrInvalidUsername):
			return nil, server.BadRequest(err, invalidUsername)
		case errors.Is(err, accounts.ErrDuplicate):
			return nil, server.Conflict(err, duplicate)
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.OK[interface{}](), nil
}

// UpsertSocialProfile updates or creates a social profile for a user
//
//	@Description	Updates or creates a social profile for a user
//	@Tags			SocialProfiles
//	@Accept			json
//	@Produce		json
//	@Param			Authorization		header		string						true	"Authorization token"
//	@Param			userIdOrMasterKey	path		string						true	"User's master key"
//	@Param			request				body		UpsertSocialProfileRequest	true	"Data to update the profile"
//	@Success		200					{object}	accounts.SocialProfile		"Updated social profile"
//	@Failure		400					{object}	server.ErrorResponse		"Invalid data format"
//	@Failure		409					{object}	server.ErrorResponse		"Username already exists"
//	@Router			/v1/users/{userIdOrMasterKey}/profiles/social [PATCH]
func (s *service) UpsertSocialProfile(
	ctx context.Context,
	req *server.Request[UpsertSocialProfileRequest, accounts.SocialProfile],
) (*server.Response[accounts.SocialProfile], *server.ErrResponse[*server.ErrorResponse]) {
	if req.Data.Username == "" && req.Data.DisplayName == "" && req.Data.Referral == "" {
		return nil, server.BadRequest(fmt.Errorf("at least one of username, displayName or referral must be provided"), invalidPropertiesErrorCode)
	}
	if server.LoggedInUser(ctx) == nil {
		return nil, server.Unauthorized(server.ErrInvalidToken)
	}
	profile, err := s.accounts.UpsertSocialProfile(ctx, req.Data.UserIDOrMasterKey, req.Data.Username, req.Data.DisplayName, req.Data.Referral, server.LoggedInUser(ctx).UserID())
	if err != nil {
		switch {
		case errors.Is(err, accounts.ErrUnauthorized):
			return nil, server.Unauthorized(err)
		case errors.Is(err, accounts.ErrInvalidUsername):
			return nil, server.BadRequest(err, invalidUsername)
		case errors.Is(err, accounts.ErrDuplicate):
			return nil, server.Conflict(err, duplicate)
		case errors.Is(err, accounts.ErrWrongReferral):
			return nil, server.BadRequest(err, invalidPropertiesErrorCode)
		default:
			return nil, server.Unexpected(err)
		}
	}

	return server.OK(profile), nil
}

// SearchSocialProfiles searches for users by keyword
//
//	@Description	Searches for users by keyword
//	@Tags			SocialProfiles
//	@Accept			json
//	@Produce		json
//	@Param			Authorization	header		string					true	"Authorization token"
//	@Param			keyword			query		string					true	"Keyword to search for"
//	@Param			limit			query		int						true	"Maximum number of results"
//	@Param			offset			query		int						true	"Offset for pagination"
//	@Param			type			query		string					true	"Search type (startsWith, contains)"
//	@Success		200				{array}		accounts.LiteUser		"List of users matching the search query"
//	@Failure		400				{object}	server.ErrorResponse	"Invalid request format"
//	@Router			/v1/user-social-profiles [GET]
func (s *service) SearchSocialProfiles(
	ctx context.Context,
	req *server.Request[SearchUserProfilesRequest, []*accounts.LiteUser],
) (*server.Response[[]*accounts.LiteUser], *server.ErrResponse[*server.ErrorResponse]) {
	if req.Data.Type != accounts.SearchTypeContains && req.Data.Type != accounts.SearchTypeStartsWith {
		return nil, server.BadRequest(fmt.Errorf("invalid search type: %s", req.Data.Type), invalidPropertiesErrorCode)
	}
	userProfiles, err := s.accounts.SearchSocialProfiles(ctx, accounts.SearchType(req.Data.Type), req.Data.Keyword, req.Data.Limit, req.Data.Offset)
	if err != nil {
		return nil, server.Unexpected(err)
	}

	return server.OK[[]*accounts.LiteUser](&userProfiles), nil
}
