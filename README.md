# netqmail-1.06-tls

this is netqmail-1.06-6 extracted source from debian package in testing with patches + TLS patch (from http://inoa.net/qmail-tls/)

How to build:

you need already installed qmail-uids-gids package or add users/groups manually acording to qmail README


$ git clone https://github.com/devane/netqmail-1.06-tls

$ cd netqmail-1.06-tls

$ dpkg-buildpackage -uc
