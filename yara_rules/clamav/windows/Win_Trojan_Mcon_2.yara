rule Win_Trojan_Mcon_2
{
strings:
	$a0 = { 6572544f31206f6666207c2025746d70203d206e756c6c207c20736f636b72656164202d662025746d70207c2069662028636f6e6e6563746564206973696e63732025746d7029207b20736f636b7772697465202d742073377363616e20465450656e61626c652173756268756e7440404032313a3a3a3124242463 }

condition:
	$a0
}

        