rule Win_Downloader_Swizzor_579
{
strings:
	$a0 = { 87207dfbe6b2e85ffd429c9ad428d1d7a421793132c7489dff1872f6261ddc9e5c209d4e1dd700c182abc9373c842297dccc585efe4a6e9e7cc8aac4b4a57daf16d675bfa71354e4a9d7061c7da3e659438ea4ac0eb1e220cd809042c0e8bd3b1f3a583ba393959722 }

condition:
	$a0
}

        
