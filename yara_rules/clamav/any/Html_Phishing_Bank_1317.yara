rule Html_Phishing_Bank_1317
{
strings:
	$a0 = { 6e6520636f6e6669726d657a2070617320766f747265206964656e746974e9206e6f757320646576726f6e732a73757370656e647265206c27616363e873206120766f74726520636f6d70746520616363c873643c2f7374726f6e673e3c2f703e3c703e766f757320646576657a20636f6e6669726d657220766f747265206964656e746974e9 }

condition:
	$a0
}

        