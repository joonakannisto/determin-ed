# determin-ed
Create deterministic ed25519 keys from seedfile and password for openssh-key-v1 format

Problem
=======
SSH keys stored on mobile devices and laptop computers are typically password protected, so that if the device is stolen or compromised the attacker has to guess the password in order to use the key. Only raw computing power limits the rate of the attacker's guesses when the key is not stored in a TPM (the TPM should withstand attacks as well). Fortunately, there are new password strengthening mechanisms, which try to minimize the computing gap between the most powerful attacker and the weakest user device. Nevertheless, the attacker advantage can be estimated to exceed 30 bits[1] of password entropy, which requires lengthy passwords or inhuman wait times.

What if the CIA filled the tanks with special jet fuel?
=======================================================
What if the attacker would not be able to confirm the key guesses without trying them on the target server?

 - Valid private key decryption should not have structure, i.e. no offline guess attackability
   - For example, RSA fails this as valid p and q have structure: namely they are prime numbers, and getting two prime numbers randomly (1/log(N) each) would be roughly one in a million chance for 1k RSA.
 - The public key should not be in the device. This unfortunately fucks up ssh-agent normal behavior.
 - OpenSSH public key query should be resistant to timing attacks

This proof of concept tool is intended to solve the first two problems (don't know anything about the last issue).

Usage
=====
Install the package (go install github.com/joonakannisto/determin-ed)

Create a key seed file.
Any tool that can output truly madly random garbage like ssh-keygen is fine for this.

 - ssh-keygen -t ed25519 -f keyseed

Not the most elegant, but doesn't matter, got entropy.

Use determin-ed to create a deterministic SSH key from the seed file

 -  determin-ed -out=id_temp keyseed
 -  cat id_temp.pub

Put the resulting public key (id_new.pub) to your target server. Delete both id_new* files.
Automate a command to create your keys when connecting to target

 - SSH does not have interactive shell command hooks so the example below does not work. If someone could patch this somehow, so that the command could find parent tty and use it, it would be nice.
 - ProxyCommand determin-ed -out=~/.ssh/id_new ~/.ssh/id_rsa.pub ; exec socket %h %p && rm ~/.ssh/id_new*

Can this be used to create password based keys?
===============================================
Yes. Should you? Maybe not. OpenSSH supports also password authentication, did you know?  




[1] Give attacker more time and parallel GPUs worth of 1M$, shittiest hardware for the user and 0.05 s wait time  https://litecoin.info/Mining_hardware_comparison
