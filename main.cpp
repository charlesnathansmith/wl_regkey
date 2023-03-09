/*********************************************
*
* WL File Key Demo
* 
* Builds a registration key file compatible with WinLicense 2.x, 3.x
* protected programs given hashes generated at protection time
* 
* No, you can't pirate anything with it, we're just examining how
* a proprietary (and rather complex) file format works here
* 
* Not affiliated with WL or Oreans in any way.
* Provide AS IS, public domain
* 
* See regkey_format.pdf for full explanation of everything going on here
* 
* Nathan
* https://github.com/charlesnathansmith/wl_regkey
*
*********************************************/

#include <stdio.h>
#include <stdint.h>
#include "wl.h"

// License hash information provided by WL at program protection time
// These could be extracted from a file or wherever, this is just a demo
const char main_hash[] = "6l51f72mCF1ZCn93ifP1O2LmHYF8d4vrpF0Toi6IcMA84sl82SI6L11WgwmLyX3a57332a7l9O18tNauR38W7v92l4wCEJcW7wY1qeqbDwI12qhlfJhplGag6z445uSD766WS4NcTyZqQD9b31pXgZ";
const char rsa1[] = "02010002820100a7039cb92a05d674622e8390826e5255a618609e95bc918d31fa0c4c531e5d49b716ae1a44e35fd90fa87235bef2741fbb63652bd1ce16569e078122d20c81eb18db50b5ca2d17f5f5ad2ba31f73cfd16365fd8b1a0c8b30feea65ff71835c18c0c447642780f90a98e8d4dc9804da655c525af2630fc3a7c9a5645fcc0294ff1b1076b6c00ea677864c60ebddb629f00c0ca5837e3cbdf1f4e3f4177cdfb2608e30bf03f4a99014af6fdc70386c9d46385af60a822ca3464b093d29ba528384b5a1ac9e23fdd3c91740e2a1adf22845905a1d18b8e993aeefbea6a5d64174643d0a4c73d38458dac6e0c5ae0993e9bbe02ce44d9c33a716e437bcc2d6ef89b90203010001028201003a09814ebf11a4427153e498351b0d3582307a72e169d3d293096778a671a8cd52f868abec406f3048c6aa598eef45f738f1035944e12ed60eb860e1aec875e5329013edf841cf4fc37dd7ea29a5df13ce4cc4dcafc2a823f09197bc3ac0012300e9b43d5394f7f5fcc8fc1f641c5ba05982ace40a1492531e398135e0f90cb941f14cb4c7b8884e8721759d109522b5aba0e821775a5b2340e4a59ae99bb8a372dd3c365e88f43c06d4c279b90996ca1d2ed168b76d2f19f447dc7b972ea7ae6987deca829f9cdf1847bc9cc147a3c313ff35b56e88c5f108f9a003aa1fc97db98da2d1e58c4582aa10f58768328ab85f25ce4557e8800541d0d30aaf6bc919028180c88152c964d53b4c1c7c6ae4c4c2060711022497afc83e257450b12eb5c52fb1ca7e1b628747cf7a88aa03f57947e8847d4ee361069ae451af1efd1fcda20c80e305e53d0a04ddc1248b6037a1cdd36ed546156fea878a0fcba9aa90929b7362488b4a0d77ff42e4c5bca5461fbab5df6457dfd1b3732f57e633bbaf8ac204cb028180d53d4ca409d9157ac7c38af0eda1087927080886e9ff4bd34a98fd15f9972b4e2a744ebe6b9d0734d62ab4e86b11bbc07e954b8610832077fa1da2899ff4ccbf996f261cfcfdfaec9326f1443077d127aafa61ab5247ff930ed44b23110691475835c271c62be941b4928a056c835b59fa7e10857640ff3395a78128da365f0b02818093ee9e870a872c6dd6629177621808dc73d711ea7c7e102410326cd79ab2f6a285550f9d5d54452711e7e66dd9628d921ae5f66b22b56b193d4c6ed3652357784c878fffbe01a31f1a785eb00d085023e8e501720626a45d4d154c4bc86f3aed5bbab11348e2a39728b12b7b96736a367cd13cc87a4ed4b2549cfcafe27f8d8b0281810061d0428da46ecda98a64aa2125ff8e1174d3fc855664e2f542ecb67b140841b7134652b08a507773c721c3e630e6eb86bb09e4a0d48631a897346cd0506d4c563f1d7b102504a3cb4d1cb9e31b907a8285ad608be3ac5f11a7e5bda9922fbf0848f030075c6ddc0b65b72a549e980a99558bea2c2e385657e537f6c9347f684d028180bcf0db7abddf45a09176c3cc048a29dca23f01ee28648a0b1e40d7f620ad9d0b924bf6deda55f86125e9ff664671cca1f41fee511f4dc50db6879f8d04cb099fc4182007cce7374643cdd9d2fcaa52277fffbfaaab05c4a81d046cb4240f9e9a6c83a2150442cb500dff27274014e53cd39d133d3dbe6cdfcb6bf5887a7d1d62";
const char rsa2[] = "0201000281808d21620c096a372ecef8381ecae935c8715b5f3b7382f00e6e06eeffb38643cd5354b1c3dd481e5525eb23c3e93008674f47cc7728fa3d34243c83c15c1f0288cd7d0833adb4c1e521e63312f95e41dd760bb029e63675d229f2652f034e2dfb2eb038a1f0919f7e759ee4af357ca6765f9c955168096976eb634bdcdaad982d0203010001028180022730ba3df3320d5398ae2e80bfa713919b286c47efb19edebc84ad3fa8118fbd30e26cba6057ca1fc3cdc3618d85e0a19bd6f98dbffceab73a2473c63bd8e0dc66e8eba07c095efe6cfa30c19969a9c62ce760b85c43f0b0978ffab48468f5b486f22c11d0f41779ebd965097a130b64d4dccdc1df300975a406e5afe1b4a10240f99187df37163cbc1eb039f424ff1ee8ec7cf876e476401728f90b8b47bc10f3552d8b02f00ed7783e591bc4f19017cc9ddd4773fee40a2c15a23ece83b65ffd024090c47523d6ef4bc194a6844e1f8fee4a65482a0881bbb1e1462055f19cfca20ed9fbdd0716190f2df11e71ad258df1aca5d0cef70e2df917f70b09a1478b97f10241006883166856d45c28d79d2b17dfea6ad2563edb7a46a072a48047131b87b5ed4f49ab61dca015470c96e790268096bc30b7277485d207436f44bc061b4bb3332d024015c3c38cc0dab73c025a4a97e83cde6986f2a38725e20f2b3c3cce4f05f82171342a9e9f5b1e275f13da2ce3083b5ff341f6b3b70705b86676f8ccd8d785d031024038f4767179cb941b96f5e99aa412bb6033f1baabaeb0e0596535c1f77d5f7dc5cdc1e899640e2db4561951a51869e8f5e2a74a806b8468b53a96da6fd3c5477b";

// License registration information
reg_info reg("Name", "Company", "Custom", "0123-4567-89AB-CDEF-FEDC-BA98-7654-3210");

// Convert arbitrary pointer x to a reference of type t
// I've probably spent too much time looking at assembly when this seems like a good idea,
// but it makes the individual license building routines easier to understand
#define ref(t, x) (*((t*)x))

int main()
{
	// Initialize main_hash key
	main_hash_key m(main_hash);

	if (!m.valid)
	{
		puts("Couldn't parse main_hash");
		return -1;
	}

	// Initialize RSA keys
	rsa_private_key pk1(rsa1), pk2(rsa2);

	if (!pk1.size() || !pk2.size())
	{
		puts("Couldn't parse RSA private keys");
		return -1;
	}

	// Set up initial buffer to hold main license body and RSA signature
	size_t signed_size = lic_main_size(reg) + pk1.size();
	uint8_t *signed_lic = new uint8_t[signed_size];

	// Build main license layers

	// Header section
	lic_build_core(ref(lic_core, signed_lic), m, reg);
	lic_build_tea(ref(lic_tea, signed_lic), reg);
	lic_build_head(ref(license_head, signed_lic), m, reg);

	// Registration strings section
	size_t str_size = lic_write_strs(signed_lic + sizeof(license_head), signed_size - sizeof(license_head), reg);
	
	// Tail section
	uint8_t *tail = signed_lic + sizeof(license_head) + str_size;
	lic_build_tail(signed_lic, ref(license_tail, tail));

	// RSA signature will come immediately after the main license body
	uint8_t *sig_pos = tail + sizeof(license_tail);

	if (!rsa_sign(signed_lic, sig_pos - signed_lic, pk1, sig_pos, pk1.size()))
	{
		puts("RSA signing failed");
		return -1;
	}

	// RSA encrypted license will be larger than signed main license
	// Need a new buffer to write it out to
	size_t fin_size = lic_final_size(signed_size, pk2);
	uint8_t *fin_lic = new uint8_t[fin_size];

	fin_size = lic_rsa_encrypt(signed_lic, signed_size, pk2, fin_lic, fin_size);

	if (!fin_size)
	{
		puts("RSA encryption failed");
		return -1;
	}

	printf("License size: %d\n\n", fin_size);
	puts("=== regkey.dat ===\n");

	for (size_t i = 0; i < fin_size; i++)
		printf("%.2X ", fin_lic[i]);

	delete[] signed_lic;
	delete[] fin_lic;
}

