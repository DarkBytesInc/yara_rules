rule Win_Downloader_Swizzor_569
{
strings:
	$a0 = { e43266275d4b41ba4cfb971efe661c5f66bbfd988043edf1600f09cc4ad2bea02c74cb9ec32bdc7c34f9bf15da8e73eea6e06a0b22705571d05ae6f68a94d099a70bb75e6d5543ce4911875355d624625f91345a7efebee9bb74fdb82873553ef32670974049937ef69a0a77bd8e5d053a4341db05085e4b68bf6742faa406660bd6b0bd99354e7af3e5790c78e42197cf }

condition:
	$a0
}

        