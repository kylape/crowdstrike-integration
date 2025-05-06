package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/gofalcon/pkg/falcon_util"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

type PaginationWriter struct {
	delegate runtime.ClientRequestWriter
	offset   int64
}

func (pr *PaginationWriter) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {
	if err := r.SetQueryParam("paginationLimit", "200"); err != nil {
		return err
	}

	if err := r.SetQueryParam("paginationOffset", strconv.FormatInt(pr.offset, 10)); err != nil {
		return err
	}

	return pr.delegate.WriteToRequest(r, reg)
}

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		println("Interrupt")
		os.Exit(0)
	}()

	var debug bool

	flag.BoolVar(&debug, "debug", false, "Debug")

	flag.Parse()

	if flag.NArg() < 2 {
		fmt.Println("Usage: crowdstrike-integration <query> <port>")
		os.Exit(1)
	}

	query := flag.Arg(0)
	aid := flag.Arg(1)

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     os.Getenv("FALCON_CLIENT_ID"),
		ClientSecret: os.Getenv("FALCON_CLIENT_SECRET"),
		Context:      context.Background(),
		Cloud:        falcon.CloudUs2,
		Debug:        debug,
	})
	if err != nil {
		panic(err)
	}

	if query == "vulns" {
		queryVulnerabilities(client, aid)
	} else if query == "components" {
		queryComponents(client, aid)
	} else {
		fmt.Printf("Invalid query option: %s. Valid choices are 'vulns' or 'components'.\n", query)
	}
}

func queryComponents(client *client.CrowdStrikeAPISpecification, aid string) {
	query := fmt.Sprintf("aid = %s | #event_simpleName = InstalledApplication | groupBy([AppName], function=selectLast([AppVersion]))", aid)
	result, err := client.Ngsiem.StartSearchV1(&ngsiem.StartSearchV1Params{
		Repository: "base_sensor",
		Body: &models.APIQueryJobInput{
			Start:       "4days",
			End:         "now",
			QueryString: &query,
		},
	})

	if err != nil {
		panic(err)
	}

	// var processedEvents int64 = 0
	var processedEvents []map[string]interface{}
	for {
		fn := func(op *runtime.ClientOperation) {
			op.Params = &PaginationWriter{
				offset:   int64(len(processedEvents)),
				delegate: op.Params,
			}
		}
		result, err := client.Ngsiem.GetSearchStatusV1(&ngsiem.GetSearchStatusV1Params{
			Repository: "base_sensor",
			ID:         *result.Payload.ID,
		}, fn)

		if err != nil {
			panic(err)
		}

		for _, event := range result.Payload.Events {
			eventMap, ok := event.(map[string]interface{})
			if !ok {
				fmt.Printf("Unexpected event type: %s\n", reflect.TypeOf(event))
				continue
			}
			processedEvents = append(processedEvents, eventMap)
		}

		if !*result.Payload.Done {
			println("Waiting for query to complete...")
			time.Sleep(5 * time.Second)
			continue
		}

		if *result.Payload.MetaData.EventCount == int64(len(processedEvents)) {
			break
		}
	}

	for _, eventMap := range processedEvents {
		fmt.Printf("%s-%s\n", eventMap["AppName"], eventMap["AppVersion"])
	}
}

func queryVulnerabilities(client *client.CrowdStrikeAPISpecification, aid string) {
	filter := fmt.Sprintf("status:'open'+aid:'%s'", aid)
	sort := ""
	vulnsBatches := make(chan []*models.DomainBaseAPIVulnerabilityV2)

	go func() {
		lastSeen := (*string)(nil)
		for {
			response, err := client.SpotlightVulnerabilities.CombinedQueryVulnerabilities(
				&spotlight_vulnerabilities.CombinedQueryVulnerabilitiesParams{
					Context: context.Background(),
					Facet:   []string{"cve", "host_info", "remediation", "evaluation_logic"},
					Filter:  filter,
					Sort:    &sort,
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

	fmt.Println("[")
	empty := true
	for vulnBatch := range vulnsBatches {
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
