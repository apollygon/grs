// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2015 The Soferox developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "soferox.h"


#include "hash.h"
#include "crypto/common.h"




using namespace std;

extern "C" {
#include <sphlib/sph_soferox.h>
} // "C"

namespace XCoin {

uint256 HashSoferox(const ConstBuf& cbuf) {
    sph_soferox512_context  ctx_gr[2];
    static unsigned char pblank[1];
    uint256 hash[4];

    sph_soferox512_init(&ctx_gr[0]);
    sph_soferox512 (&ctx_gr[0], cbuf.P ? cbuf.P : pblank, cbuf.Size);
    sph_soferox512_close(&ctx_gr[0], static_cast<void*>(&hash[0]));

	sph_soferox512_init(&ctx_gr[1]);
	sph_soferox512(&ctx_gr[1],static_cast<const void*>(&hash[0]), 64);
	sph_soferox512_close(&ctx_gr[1],static_cast<void*>(&hash[2]));

    return hash[2];
}

uint256 HashFromTx(const ConstBuf& cbuf) {
	CSHA256 sha;
	sha.Write(cbuf.P, cbuf.Size);
	uint256 r;
	sha.Finalize((unsigned char*)&r);
	return r;
}

uint256 HashForSignature(const ConstBuf& cbuf) {
	CSHA256 sha;
	sha.Write(cbuf.P, cbuf.Size);
	uint256 r;
	sha.Finalize((unsigned char*)&r);
	return r;
}

void SoferoxHasher::Finalize(unsigned char h[32]) {
	auto c = (sph_soferox512_context*)ctx;
	uint256 hash[4];
	sph_soferox512_close(c, static_cast<void*>(&hash[0]));

	sph_soferox512_context  c2;
	sph_soferox512_init(&c2);
	sph_soferox512(&c2, static_cast<const void*>(&hash[0]), 64);
	sph_soferox512_close(&c2, static_cast<void*>(&hash[2]));
	memcpy(h, static_cast<void*>(&hash[2]), 32);
}

SoferoxHasher& SoferoxHasher::Write(const unsigned char *data, size_t len) {
	auto c = (sph_soferox512_context*)ctx;
	sph_soferox512(c, data, len);
	return *this;
}

SoferoxHasher::SoferoxHasher() {
	auto c = new sph_soferox512_context;
	ctx = c;
	sph_soferox512_init(c);
}

SoferoxHasher::SoferoxHasher(SoferoxHasher&& x)
	:	ctx(x.ctx)
{
	x.ctx = 0;
}

SoferoxHasher::~SoferoxHasher() {
	delete (sph_soferox512_context*)ctx;
}

SoferoxHasher& SoferoxHasher::operator=(SoferoxHasher&& x)
{
	delete (sph_soferox512_context*)ctx;
	ctx = x.ctx;
	x.ctx = 0;
	return *this;
}

} // XCoin::

