package main

import (
	"context"
	"fmt"
	"os"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
)

func main() {
	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     os.Getenv("FALCON_CLIENT_ID"),
		ClientSecret: os.Getenv("FALCON_CLIENT_SECRET"),
		Context:      context.Background(),
		Cloud:        falcon.CloudUs2,
	})
	if err != nil {
		panic(err)
	}

	emptyStr := ""
	vulnerabilityBatches := queryVulnerabilities(client, "status:'open'", &emptyStr)

	fmt.Println("[")
	empty := true
	for vulnBatch := range vulnerabilityBatches {
		for _, vuln := range vulnBatch {
			json, err := falcon_util.PrettyJson(vuln)
			if err != nil {
				panic(err)
			}
			if !empty {
				json = "," + json
			} else {
				empty = false
			}

			fmt.Printf("%s", json)
		}
	}
	fmt.Println("]")
}

func queryVulnerabilities(client *client.CrowdStrikeAPISpecification, filter string, sort *string) <-chan []*models.DomainBaseAPIVulnerabilityV2 {
	vulnsBatches := make(chan []*models.DomainBaseAPIVulnerabilityV2)

	go func() {
		lastSeen := (*string)(nil)
		for {
			response, err := client.SpotlightVulnerabilities.CombinedQueryVulnerabilities(
				&spotlight_vulnerabilities.CombinedQueryVulnerabilitiesParams{
					Context: context.Background(),
					Facet:   []string{"cve", "host_info", "remediation", "evaluation_logic"},
					Filter:  filter,
					Sort:    sort,
					After:   lastSeen,
				},
			)

			if err != nil {
				panic(falcon.ErrorExplain(err))
			}
			if err = falcon.AssertNoError(response.Payload.Errors); err != nil {
				panic(err)
			}

			vulns := response.Payload.Resources
			if len(vulns) == 0 {
				break
			}

			vulnsBatches <- vulns

			if response.Payload.Meta == nil && response.Payload.Meta.Pagination == nil && response.Payload.Meta.Pagination.Limit == nil {
				panic("Cannot paginate Vulnerabilities, pagination information missing")
			}
			// Convert limit to int (the wider type) to avoid overflow
			if int(*response.Payload.Meta.Pagination.Limit) > len(vulns) {
				// We have got less items than what was the limit. Meaning, this is last batch, continuation is futile.
				break
			} else {
				lastSeen = response.Payload.Meta.Pagination.After
			}
		}
		close(vulnsBatches)
	}()

	return vulnsBatches
}
