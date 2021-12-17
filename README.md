# PROTONVD: Protobuf definitions for NVD

Features:
* Encapsulates all fields in the [NIST NVD Vulnerability JSON feeds](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED).
* JSON annotations in proto definitions for JSON marshalling/unmarshalling.
* A bash script to assist in downloading JSON feeds.

The protobuf definition has been precompiled for easy import and usage.

## Parsing JSON
```go
import "github.com/fkautz/protonvd"
import "google.golang.org/protobuf/encoding/protojson"

msg := &protonvd.NvdMessage{}
err := protojson.Unmarshal([]byte(str), msg)

buf, err := protojson.Marshal(msg)
```


## Emitting JSON

```go
import "github.com/fkautz/protonvd"
import "google.golang.org/protobuf/encoding/protojson"

msg := &protonvd.NvdMessage{
	// ...
}

jsonBytes, err := protojson.Marshal(msg)
```

## Notes

There is one minor departure from the spec.

`//:root/CVE_data_numberOfCVEs` is an integer rather than a string.
Emitted JSON for this field is an `int32` instead of a `string`.

```json
{
    "CVE_data_numberOfCVEs": 1,
    // ...
}
```

instead of

```json
{
    "CVE_data_numberOfCVEs": "1",
    // ...
}
```
