rule Win_Trojan_Ciadoor_158
{
strings:
	$a0 = { 289bc94cb31c7b5b1fd1430fc1fc0421ae5b0c4b05f90a5b989a8154f2d02b7fa8252bbdfb59895a1f2d3c6c35b20e5bb5b1a56677f910cde7b11187b301ca63c70c988adfa1f162372dee97219d4103cd1c51b3d29891ebcc545ab4a7ad21ef3d8e262bf5ab2cdf40e1d147914d24741fad31d1cf74237aa392eacbcf913c93f2a06957b80c0e5011a12554 }

condition:
	$a0
}

        