package parameterstore

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
)

type Parameters struct {
	readIndex  int64
	bytesJSON  []byte
	basePath   string
	parameters map[string]*Parameter
}

type Parameter struct {
	Key              string
	Value            *string
	Version          int64
	LastModifiedDate time.Time
}

func (p *Parameter) GetValue() string {
	if p.Value == nil {
		return ""
	}
	return *p.Value
}

func NewParameters(bp string, parameters map[string]*Parameter) *Parameters {
	return &Parameters{
		basePath:   bp,
		parameters: parameters,
	}
}

func (ps *Parameters) Read(des []byte) (n int, err error) {
	if ps.bytesJSON == nil {
		ps.bytesJSON, err = json.Marshal(ps.getKeyValueMap())
		if err != nil {
			return 0, err
		}
	}

	if ps.readIndex >= int64(len(ps.bytesJSON)) {
		ps.readIndex = 0
		return 0, io.EOF
	}

	n = copy(des, ps.bytesJSON[ps.readIndex:])
	ps.readIndex += int64(n)

	return n, nil
}

func (ps *Parameters) GetFullPath(name string) string {
	return ps.basePath + name
}

func (ps *Parameters) GetByFullPath(p string) *Parameter {
	name := strings.Replace(p, ps.basePath, "", 1)

	parameter, ok := ps.parameters[name]
	if !ok {
		return nil
	}

	return parameter
}

func (ps *Parameters) ExistsByFullPath(p string) bool {
	name := strings.Replace(p, ps.basePath, "", 1)
	_, ok := ps.parameters[name]

	return ok
}

func (ps *Parameters) GetValueByFullPath(p string) string {
	parameter := ps.GetByFullPath(p)
	if parameter == nil {
		return ""
	}

	return parameter.GetValue()
}

func (ps *Parameters) Get(name string) *Parameter {
	parameter, ok := ps.parameters[name]
	if !ok {
		return nil
	}

	return parameter
}

func (ps *Parameters) Exists(name string) bool {
	_, ok := ps.parameters[name]
	return ok
}

func (ps *Parameters) GetValueByName(name string) string {
	parameter := ps.Get(name)
	if parameter == nil {
		return ""
	}

	return parameter.GetValue()
}

func (ps *Parameters) Decode(output any) error {
	return mapstructure.Decode(ps.getKeyValueMap(), output)
}

func (ps *Parameters) getKeyValueMap() map[string]string {
	kv := make(map[string]string, len(ps.parameters))
	for k, v := range ps.parameters {
		kv[k] = v.GetValue()
	}

	return kv
}
