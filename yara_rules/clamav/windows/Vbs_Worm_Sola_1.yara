rule Vbs_Worm_Sola_1
{
strings:
	$a0 = { 617474726962202d73202d68202d72202525693a5c6175746f72756e2e696e6626636f7079202f7920257365747570255c6175746f72756e2e696e66202525693a5c6175746f72756e2e696e6626617474726962202525693a5c6175746f72756e2e696e66202b73202b68202b72266d64202525693a5c736f6c6126636f7079202f792022257365747570255c736f6c612e626174 }

condition:
	$a0
}

        