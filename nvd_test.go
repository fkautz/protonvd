package protonvd

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"io/ioutil"
	"testing"
)

var str = `
{
  "CVE_data_type": "CVE",
  "CVE_data_format": "MITRE",
  "CVE_data_version": "4.0",
  "CVE_data_numberOfCVEs": "1",
  "CVE_data_timestamp": "2021-12-06T08:00Z",
  "CVE_Items": [
    {
      "cve": {
        "data_type": "CVE",
        "data_format": "MITRE",
        "data_version": "4.0",
        "CVE_data_meta": {
          "ID": "CVE-2021-0001",
          "ASSIGNER": "secure@intel.com"
        },
        "problemtype": {
          "problemtype_data": [
            {
              "description": [
                {
                  "lang": "en",
                  "value": "CWE-203"
                }
              ]
            }
          ]
        },
        "references": {
          "reference_data": [
            {
              "url": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00477.html",
              "name": "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00477.html",
              "refsource": "MISC",
              "tags": [
                "Patch",
                "Vendor Advisory"
              ]
            }
          ]
        },
        "description": {
          "description_data": [
            {
              "lang": "en",
              "value": "Observable timing discrepancy in Intel(R) IPP before version 2020 update 1 may allow authorized user to potentially enable information disclosure via local access."
            }
          ]
        }
      },
      "configurations": {
        "CVE_data_version": "4.0",
        "nodes": [
          {
            "operator": "OR",
            "children": [],
            "cpe_match": [
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:integrated_performance_primitives_cryptography:2019:-:*:*:*:*:*:*",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:integrated_performance_primitives_cryptography:2019:update_1:*:*:*:*:*:*",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:integrated_performance_primitives_cryptography:2019:update_2:*:*:*:*:*:*",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:integrated_performance_primitives_cryptography:2019:update_3:*:*:*:*:*:*",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:integrated_performance_primitives_cryptography:2019:update_4:*:*:*:*:*:*",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:integrated_performance_primitives_cryptography:2020:-:*:*:*:*:*:*",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:sgx_dcap:*:*:*:*:*:linux:*:*",
                "versionEndIncluding": "1.10.100.4",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:sgx_dcap:*:*:*:*:*:windows:*:*",
                "versionEndIncluding": "1.10.100.4",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:sgx_psw:*:*:*:*:*:windows:*:*",
                "versionEndIncluding": "2.12.100.4",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:sgx_psw:*:*:*:*:*:linux:*:*",
                "versionEndIncluding": "2.13.100.4",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:sgx_sdk:*:*:*:*:*:windows:*:*",
                "versionEndIncluding": "2.12.100.4",
                "cpe_name": []
              },
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:intel:sgx_sdk:*:*:*:*:*:linux:*:*",
                "versionEndIncluding": "2.13.100.4",
                "cpe_name": []
              }
            ]
          }
        ]
      },
      "impact": {
        "baseMetricV3": {
          "cvssV3": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "attackVector": "LOCAL",
            "attackComplexity": "HIGH",
            "privilegesRequired": "LOW",
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "NONE",
            "availabilityImpact": "NONE",
            "baseScore": 4.7,
            "baseSeverity": "MEDIUM"
          },
          "exploitabilityScore": 1,
          "impactScore": 3.6
        },
        "baseMetricV2": {
          "cvssV2": {
            "version": "2.0",
            "vectorString": "AV:L/AC:L/Au:N/C:P/I:N/A:N",
            "accessVector": "LOCAL",
            "accessComplexity": "LOW",
            "authentication": "NONE",
            "confidentialityImpact": "PARTIAL",
            "integrityImpact": "NONE",
            "availabilityImpact": "NONE",
            "baseScore": 2.1
          },
          "severity": "LOW",
          "exploitabilityScore": 3.9,
          "impactScore": 2.9,
          "acInsufInfo": true,
          "obtainAllPrivilege": true,
          "obtainUserPrivilege": true,
          "obtainOtherPrivilege": true,
          "userInteractionRequired": true
        }
      },
      "publishedDate": "2021-06-09T20:15Z",
      "lastModifiedDate": "2021-06-28T18:03Z"
    }
  ]
}
`

func TestLoad(t *testing.T) {

	msg := &NvdMessage{}

	err := protojson.Unmarshal([]byte(str), msg)
	assert.NoError(t, err)

	_, err = protojson.Marshal(msg)
	assert.NoError(t, err)
}

func TestLoadLarge(t *testing.T) {
	_, err := ioutil.ReadDir("./data/years")
	if err != nil {
		t.Skipf("please download the NVD dataset to run a full test")
	}
	data, err := ioutil.ReadFile("./data/years/2021.json")
	assert.NoError(t, err)

	msg := &NvdMessage{}
	err = protojson.Unmarshal(data, msg)
	assert.NoError(t, err)

	assert.Len(t, msg.CveItems, int(msg.CveDataNumberOfCves))
}

func TestFullLoad(t *testing.T) {
	dir, err := ioutil.ReadDir("./data/years")
	if err != nil {
		t.Skipf("please download the NVD dataset to run a full test")
	}
	assert.NoError(t, err)
	count := 0
	for _, file := range dir {
		path := fmt.Sprintf("./data/years/%s", file.Name())
		data, err := ioutil.ReadFile(path)
		assert.NoError(t, err)

		msg := &NvdMessage{}
		err = protojson.Unmarshal(data, msg)
		assert.NoError(t, err)

		assert.Len(t, msg.CveItems, int(msg.CveDataNumberOfCves))
		count = count + int(msg.CveDataNumberOfCves)
	}
}

func BenchmarkLoadSingleJson(b *testing.B) {
	count := 0
	for i := 0; i < b.N; i++ {
		msg := &NvdMessage{}

		err := protojson.Unmarshal([]byte(str), msg)
		assert.NoError(b, err)
		count = count + int(msg.CveDataNumberOfCves)
	}
	b.StopTimer()
}

func BenchmarkSerializeSingleJson(b *testing.B) {
	count := 0
	msg := &NvdMessage{}
	err := protojson.Unmarshal([]byte(str), msg)
	assert.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = protojson.Marshal(msg)
		assert.NoError(b, err)
		count = count + int(msg.CveDataNumberOfCves)
	}
	b.StopTimer()
}

func BenchmarkLoadSingleProto(b *testing.B) {
	count := 0
	msg := &NvdMessage{}

	err := protojson.Unmarshal([]byte(str), msg)
	assert.NoError(b, err)

	data, err := proto.Marshal(msg)
	assert.NoError(b, err)

	for i := 0; i < b.N; i++ {
		err = proto.Unmarshal(data, msg)
		assert.NoError(b, err)
		count = count + int(msg.CveDataNumberOfCves)
	}
	b.StopTimer()
}

func BenchmarkSerializeSingleProto(b *testing.B) {
	count := 0
	msg := &NvdMessage{}
	err := protojson.Unmarshal([]byte(str), msg)
	assert.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = proto.Marshal(msg)
		assert.NoError(b, err)
		count = count + int(msg.CveDataNumberOfCves)
	}
	b.StopTimer()
}
