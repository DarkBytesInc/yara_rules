rule Win_Downloader_Agent_31911
{
strings:
	$a0 = { 9c754b89a5d16adecd5e10b0e977cda0810dc2c5ce1e77c83f18fe76d89fc2aa3f4691ca83c1fcedc6ab14b846677753b3b95d26bb34732e4ed669b7672a82022730eac659cd048d099b7a68455cd7461205a37bfcc8b38c26f1d0ce9dd0267b2d620b4ca7618bc4abb3aec0b34a }

condition:
	$a0
}

        
