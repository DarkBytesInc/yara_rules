rule Win_Downloader_Agent_31790
{
strings:
	$a0 = { fd3bae986cc2bfa404ca2e5c0f31c06dcbc62c0900c09641ba866958079fd2a71ac2d7f40011552004c0215c071dd1ed0159d65cc4ced7521c7e7c93d3cfd725fca91760dd1eda560dc377570dc85229d723d42d0ec0c1275ac48dfefcc38f4907b2b1783bd26427fcd7bfda8ac32e4dfcefa3cb0f7cc95c }

condition:
	$a0
}

        
