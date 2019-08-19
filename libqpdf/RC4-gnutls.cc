#include <qpdf/RC4.hh>
#include <qpdf/QUtil.hh>


RC4::RC4(unsigned char const* key_data, int key_len)
{
    if (key_len == -1)
    {
	key_len = strlen(reinterpret_cast<char const*>(key_data));
    }

    int ret;
    gnutls_cipher_algorithm_t alg = GNUTLS_CIPHER_ARCFOUR_128;
    gnutls_datum_t key;

    key.data = const_cast<unsigned char*>(key_data);
    key.size = key_len;

    ret = gnutls_cipher_init(&(this->ctx),
                             alg,
                             &key,
                             NULL);
    if (ret < 0)
    {
	QUtil::throw_system_error(
	    std::string("GNU TLS: RC4 error: ") + std::string(gnutls_strerror(ret)));
	this->ctx = nullptr;
    }
}

RC4::~RC4()
{
    if (this->ctx != nullptr)
	gnutls_cipher_deinit(this->ctx);
}

void
RC4::process(unsigned char *in_data, int len, unsigned char* out_data)
{
    if (out_data == 0)
    {
	// Convert in place
	out_data = in_data;
    }

    if (this->ctx != nullptr && in_data != nullptr && len > 0)
	gnutls_cipher_encrypt2(this->ctx, in_data, len, out_data, len);
}
