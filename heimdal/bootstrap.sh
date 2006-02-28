${LIBTOOLIZE:-libtoolize} --automake &&
${ACLOCAL:-aclocal} && \
${AUTOMAKE:-automake} --add-missing && \
${AUTOCONF:-autoconf}
