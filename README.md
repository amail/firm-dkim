# firm-dkim

Use this library to create DKIM signatures from your C or C++ applications.


## Getting started

Follow these steps to easily sign your e-mails using [DomainKeys Identified Mail](http://en.wikipedia.org/wiki/DomainKeys_Identified_Mail) (DKIM).

*Confused? Don't know how to use it? Still want to sign your mails with DKIM? Have a look at [AlphaMail](http://comfirm.se/alpha-mail/) instead. AlphaMail is a platform for sending transactional e-mail. We will get you up and started in minutes. You're just a web service call away!*

**Downloading the library**

Just head over to our project download page:
[Download](https://github.com/comfirm/firm-dkim/downloads)

Install the library by doing the following:
	$ make
	# make install

**Create an application in either C/C++**

**1)** Add this line to your headers
	#include <firm-dkim>

**2)** Set some settings
	/* settings */
	char *private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQChJ21Ygf8M5BU/3IPU7OtTDIZGTbjMx9lIoypt53jqIUTNH4B7\nX9zDsJrLrbMjDXW1NjR26u4xizra9v7Q/ZpysvBPYuAj2C9nY/uVwAju53wFm4K0\nEhUNii0eS4xmgbZYow+pox5fh1hGJY15eldbzfEVp3AUy0gZOfm82V6pywIDAQAB\nAoGAG1imbHt6vURC+tg/orUlZa1dZ7auoklTbMkLXSUHVquYkjpDQixNOQPR8Lgk\nCtGw5LQzCO7qxot6zEdXjD1MpN8RSGCmRgPU+PRS+7g1fuQSEECAM0U7urEx0knS\nUoRN1akSiDnWxs/LV/bVS243FK5CSiEeQsD3HIv8+ItfRzECQQDSFiRz3QCETLOo\nWJrnJSF1FLnZsHlEzghUs+TZOr1WgPtWcq9SFqKuo3n+3SD9SChFXJ4LGiIxNy12\n3sKP+dyDAkEAxF+f5bhspHRCZqxNQK4MtukeWYJnPhiXegOJm9UGf5zoM36Vzgav\n08ysnD5Y0nMzUYp9p8pcO7BvM4VQyT+LGQJBAMzlh5vxGcXuwPIZqMpzblQwaKql\n8UBn6bwiz7oGDg/GMFu58sAPD49gJWWq6bfdnlk34XRWgq6ZcCAVVpDxUl0CQC+R\nRkc8FD0F2GvMgu4O+w93ip1+BAo7pL2ui6/Ou0NAO9L1b843OnIgmxNB2vwnYZ/3\n3xY843il9VnSik4lcUkCQQC/7mUEU5AKGBTUktKoARXuUUpiDmPSvv6GH1NNNHqz\ncs9Bre0dpzuQAPQ7e2CLbGSwArllvWn3zZZ3TGytCZCw\n-----END RSA PRIVATE KEY-----";
	char *domain = "comfirm.se";
	char *selector = "mail1";

**3)** Set headers
	/* headers */
	int headerc = 4;
	int i = 0;
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

**4)** Set the message body
	/* body */
	char *body = "Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.";

**5)** Create the signature
	/* create signature */
	char *dkim = dkim_create(headers, headerc, body, private_key, domain, selector, 0);
	printf ("DKIM-Signature: %s\n", dkim);

**6)** Free used memory 
	/* free some memory */
	free (dkim);

	for (i = 0; i < headerc; ++i) {
		free (headers[i]);
	}
	free (headers);

**7)** Congratulations!

You've just signed your first e-mail with firm-dkim. See it as the first of many!

**Any questions, bugs, or just feel like sending some love?<br />
Head over to our site ([contact us](http://comfirm.se/kontakta-oss/)) and we will get back to you shortly.**

