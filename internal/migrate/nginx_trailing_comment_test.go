package migrate

import (
	"reflect"
	"strings"
	"testing"
)

// A trailing "# comment" after a directive is not part of its value, and a
// brace inside a comment does not move the block depth (F21700).
func TestParseNginxTrailingComments(t *testing.T) {
	plain := `server {
    listen 80;
    server_name example.com www.example.com;
    root /var/www/html;
    index index.php index.html;
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }
}
`
	commented := `server {
    listen 80; # http
    server_name example.com www.example.com; # main site
    root /var/www/html; # docroot
    index index.php index.html; # idx
    location / { # open }
        try_files $uri $uri/ /index.php?$args; # front controller
    } # close {
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.2-fpm.sock; # fpm
    }
} # end of server
`
	want, err := ParseNginx(strings.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseNginx(strings.NewReader(commented))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("commented config parsed differently:\nwant %+v\ngot  %+v", want, got)
	}
}

func TestParseNginxKeepsHashInsideValues(t *testing.T) {
	src := `server {
    server_name example.com;
    root /var/www/a#b; # real comment
    location /app/ {
        proxy_pass http://127.0.0.1:3000/#frag; # c
    }
    location /priv/ {
        deny all; # }
    }
}
`
	got, err := ParseNginx(strings.NewReader(src))
	if err != nil || len(got) != 1 {
		t.Fatalf("parse: %v %+v", err, got)
	}
	c := got[0]
	if c.Root != "/var/www/a#b" {
		t.Errorf("root = %q, want /var/www/a#b", c.Root)
	}
	if len(c.Locations) != 2 || c.Locations[0].ProxyPass != "http://127.0.0.1:3000/#frag" || !c.Locations[1].DenyAll {
		t.Errorf("locations = %+v", c.Locations)
	}
}

func TestStripNginxComment(t *testing.T) {
	cases := map[string]string{
		"listen 80; # http":            `listen 80; `,
		"# whole line":                 "",
		"root /a#b;":                   "root /a#b;",
		`add_header X "a # b"; # c`:    `add_header X "a # b"; `,
		`add_header X 'a # b';`:        `add_header X 'a # b';`,
		`add_header X "a \" # b"; # c`: `add_header X "a \" # b"; `,
		"server_name a.com;#tight":     "server_name a.com;",
		"":                             "",
	}
	for in, want := range cases {
		if got := stripNginxComment(in); got != want {
			t.Errorf("stripNginxComment(%q) = %q, want %q", in, got, want)
		}
	}
}
