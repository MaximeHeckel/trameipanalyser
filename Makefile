analyseur:
	gcc -Wall -o analyseur analyseur.c -lpcap

clean: 
	rm -v analyseur
