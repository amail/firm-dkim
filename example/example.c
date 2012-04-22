/*
The MIT License

Copyright (c) 2012 Comfirm <http://www.comfirm.se/>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include <stdio.h>
#include <string.h>

#include <firm-dkim.h>


int main(int argc, char *argv[]) {
	int i = 0;

	/* settings */
	char *private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQChJ21Ygf8M5BU/3IPU7OtTDIZGTbjMx9lIoypt53jqIUTNH4B7\nX9zDsJrLrbMjDXW1NjR26u4xizra9v7Q/ZpysvBPYuAj2C9nY/uVwAju53wFm4K0\nEhUNii0eS4xmgbZYow+pox5fh1hGJY15eldbzfEVp3AUy0gZOfm82V6pywIDAQAB\nAoGAG1imbHt6vURC+tg/orUlZa1dZ7auoklTbMkLXSUHVquYkjpDQixNOQPR8Lgk\nCtGw5LQzCO7qxot6zEdXjD1MpN8RSGCmRgPU+PRS+7g1fuQSEECAM0U7urEx0knS\nUoRN1akSiDnWxs/LV/bVS243FK5CSiEeQsD3HIv8+ItfRzECQQDSFiRz3QCETLOo\nWJrnJSF1FLnZsHlEzghUs+TZOr1WgPtWcq9SFqKuo3n+3SD9SChFXJ4LGiIxNy12\n3sKP+dyDAkEAxF+f5bhspHRCZqxNQK4MtukeWYJnPhiXegOJm9UGf5zoM36Vzgav\n08ysnD5Y0nMzUYp9p8pcO7BvM4VQyT+LGQJBAMzlh5vxGcXuwPIZqMpzblQwaKql\n8UBn6bwiz7oGDg/GMFu58sAPD49gJWWq6bfdnlk34XRWgq6ZcCAVVpDxUl0CQC+R\nRkc8FD0F2GvMgu4O+w93ip1+BAo7pL2ui6/Ou0NAO9L1b843OnIgmxNB2vwnYZ/3\n3xY843il9VnSik4lcUkCQQC/7mUEU5AKGBTUktKoARXuUUpiDmPSvv6GH1NNNHqz\ncs9Bre0dpzuQAPQ7e2CLbGSwArllvWn3zZZ3TGytCZCw\n-----END RSA PRIVATE KEY-----";
	char *domain = "comfirm.se";
	char *selector = "mail1";
	
	/* headers */
	int headerc = 4;
	stringpair **headers = (stringpair**)malloc(sizeof(stringpair*) * headerc);
	
	for (i = 0; i < headerc; ++i) {
		headers[i] = (stringpair*)malloc(sizeof(stringpair));
	}
	
	headers[0]->key = "From";
	headers[0]->value = "\"Comfirm\" <noreply@comfirm.se>";
	
	headers[1]->key = "To";
	headers[1]->value = "\"Example\" <john.doe@example.com>";
	
	headers[2]->key = "Subject";
	headers[2]->value = "Is dinner ready?";

	headers[3]->key = "Message-ID";
	headers[3]->value = "<20030712040037.46341.5F8J@football.example.com>";		
	
	/* body */
	char *body = "Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.";
	
	/* create signature */
	char *dkim = dkim_create(headers, headerc, body, private_key, domain, selector, 0);
	printf ("DKIM-Signature: %s\n", dkim);

	/* free some memory */
	free (dkim);

	for (i = 0; i < headerc; ++i) {
		free (headers[i]);
	}
	free (headers);

	return 0;
}


