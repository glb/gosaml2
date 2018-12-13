package saml2_test

import (
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	"github.com/stretchr/testify/require"
)

func Test_VerifyAssertionConditions_NotBefore(t *testing.T) {
	tcs := []struct {
		name             string
		actualClockSkew  time.Duration
		allowedClockSkew time.Duration
		check            func(t *testing.T, w *saml2.WarningInfo, err error)
	}{
		{
			name: "no actual skew, no allowed skew, assertion should validate",
			check: func(t *testing.T, w *saml2.WarningInfo, err error) {
				require.NoError(t, err)
				require.Equal(t, false, w.InvalidTime)
			},
		},
		{
			name:             "no actual skew, some allowed skew, assertion should have no InvalidTime warning",
			allowedClockSkew: 30 * time.Second,
			check: func(t *testing.T, w *saml2.WarningInfo, err error) {
				require.NoError(t, err)
				require.Equal(t, false, w.InvalidTime)
			},
		},
		{
			name:             "actual skew within allowed skew, assertion should have no InvalidTime warning",
			actualClockSkew:  10 * time.Second,
			allowedClockSkew: 30 * time.Second,
			check: func(t *testing.T, w *saml2.WarningInfo, err error) {
				require.NoError(t, err)
				require.Equal(t, false, w.InvalidTime)
			},
		},
		{
			name:             "actual skew outside allowed skew, assertion should have InvalidTime warning",
			actualClockSkew:  60 * time.Second,
			allowedClockSkew: 30 * time.Second,
			check: func(t *testing.T, w *saml2.WarningInfo, err error) {
				require.NoError(t, err)
				require.Equal(t, true, w.InvalidTime)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			sp := &saml2.SAMLServiceProvider{
				AllowedClockSkew: tc.allowedClockSkew,
			}

			now := time.Now().UTC().Truncate(time.Millisecond)

			assertion := &types.Assertion{
				Conditions: &types.Conditions{
					NotBefore:    now.Add(tc.actualClockSkew).Format(time.RFC3339),
					NotOnOrAfter: now.Add(5 * time.Minute).Format(time.RFC3339),
				},
			}

			w, err := sp.VerifyAssertionConditions(assertion)

			tc.check(t, w, err)
		})
	}
}
