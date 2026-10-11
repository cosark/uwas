package migrate

import (
	"fmt"
	"strings"
	"testing"
)

func f3800conv(t *testing.T, tf string) (bool, string) {
	in := "server {\n listen 80;\n server_name a.com;\n root /var/www/a;\n location / {\n try_files " + tf + ";\n }\n location ~ \\.php$ {\n fastcgi_pass unix:/run/php/php-fpm.sock;\n }\n}\n"
	cfgs, err := ParseNginx(strings.NewReader(in))
	if err != nil || len(cfgs) != 1 {
		t.Fatalf("parse: %v", err)
	}
	d := ConvertToUWAS(cfgs)[0]
	return d.SPAMode, d.Type
}

func TestNginxPHPFrontControllerNotSPAMode(t *testing.T) {
	// control: static-site SPA fallback to index.html is a real SPA
	if spa, _ := f3800conv(t, "$uri $uri/ /index.html"); !spa {
		t.Fatal("invalid proof: control lost SPAMode")
	}
	spa, typ := f3800conv(t, "$uri $uri/ /index.php?$args")
	fmt.Printf("EXPECTED: SPAMode=false for php front controller (type=%s)\nACTUAL: SPAMode=%v\n", typ, spa)
	if spa {
		fmt.Println("PROBLEM CONFIRMED")
		t.FailNow()
	}
	fmt.Println("PROBLEM NOT REPRODUCED")
}
