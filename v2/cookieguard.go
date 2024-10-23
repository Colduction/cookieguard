package cookieguard

import (
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// New creates a new middleware handler
func New(config ...Config) fiber.Handler {
	// Set default config
	cfg := configDefault(config...)

	// Return new handler
	return func(c *fiber.Ctx) error {
		// Skip middleware if Next returns true
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		var oldKeys [][]byte

		// Decrypt request cookies
		c.Request().Header.VisitAllCookie(func(key, value []byte) {
			if cfg.EncryptKeys {
				decryptedKey, err := cfg.Decryptor(key, cfg.Key)
				if err != nil {
					if cfg.SkipUnencryptedCookies {
						oldKeys = append(oldKeys, key)
						return
					}
					if !cfg.SuppressErrors {
						panic(err)
					}
				} else {
					oldKeys = append(oldKeys, key)
					key = decryptedKey
				}
			}

			if !isDisabledBytesK(key, cfg.Except) {
				if cfg.EncryptValues {
					decryptedValue, err := cfg.Decryptor(value, cfg.Key)
					if err != nil {
						if cfg.SkipUnencryptedCookies {
							oldKeys = append(oldKeys, key)
							return
						}
						if cfg.SuppressErrors {
							c.Request().Header.SetCookieBytesKV(key, value)
							return
						}
						c.Request().Header.SetCookieBytesKV(key, nil)
						return
					}
					value = decryptedValue
				}
				c.Request().Header.SetCookieBytesKV(key, value)
			}
		})

		if cfg.EncryptKeys {
			for _, key := range oldKeys {
				c.Request().Header.DelCookieBytes(key)
			}
		}

		// Continue stack
		err := c.Next()

		// Encrypt response cookies
		c.Response().Header.VisitAllCookie(func(key, value []byte) {
			if !isDisabledBytesK(key, cfg.Except) {
				var encryptedCookie fasthttp.Cookie
				encryptedCookie.SetKeyBytes(key)

				if c.Response().Header.Cookie(&encryptedCookie) {
					if cfg.EncryptKeys {
						encryptedKey, err := cfg.Encryptor(encryptedCookie.Key(), cfg.Key)
						if err != nil {
							if cfg.SuppressErrors {
								c.Response().Header.SetCookie(&encryptedCookie)
								return
							}
							panic(err)
						}
						oldKeys = append(oldKeys, key)
						key = encryptedKey
						encryptedCookie.SetKeyBytes(key)
					}

					if cfg.EncryptValues {
						encryptedValue, err := cfg.Encryptor(encryptedCookie.Value(), cfg.Key)
						if err != nil {
							if cfg.SuppressErrors {
								c.Response().Header.SetCookie(&encryptedCookie)
								return
							}
							panic(err)
						}
						value = encryptedValue
					}
					encryptedCookie.SetValueBytes(value)
					c.Response().Header.SetCookie(&encryptedCookie)
				}
			}
		})

		if cfg.EncryptKeys {
			for _, key := range oldKeys {
				c.Response().Header.DelCookieBytes(key)
			}
		}

		return err
	}
}
