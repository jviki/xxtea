all: compile-xxtea run-tests
compile-xxtea: xxtea
run-tests: test-noise512 test-seq

############

xxtea:
	$(MAKE) -C ..
	ln -f ../xxtea $@

test-seq:
	./xxtea -c -i seq.open -o seq.crypt.test -k key.txt
	diff seq.crypt.test seq.crypt
	./xxtea -d -i seq.crypt.test -o seq.open.test -k key.txt
	diff seq.open.test seq.open

test-noise512:
	./xxtea -c -i noise512.open -o noise512.crypt.test -k key.txt
	diff noise512.crypt.test noise512.crypt
	./xxtea -d -i noise512.crypt.test -o noise512.open.test -k key.txt
	diff noise512.open.test noise512.open

clean:
	$(RM) xxtea
	$(RM) seq.open.test seq.crypt.test
	$(RM) noise512.open.test noise512.crypt.test
