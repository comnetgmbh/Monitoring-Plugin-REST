#!/bin/bash -e

# Cleanup
if [ -f Makefile ]; then
	make clean
	rm Makefile.old
fi

# Run build once to update build-generated files
perl Makefile.PL
make
make test

# Package
make dist

# Cleanup
make clean
rm Makefile.old
