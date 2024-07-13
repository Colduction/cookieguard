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
		// Don't execute middleware if Next returns true
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		var oldKeys = make([][]byte, 0)

		// Decrypt request cookies
		c.Request().Header.VisitAllCookie(func(key, value []byte) {
			if cfg.EncryptKey {
				b, err := cfg.Decryptor(key, cfg.Key)
				if err != nil {
					if !cfg.ReturnOriginalOnError {
						panic(err)
					}
				} else {
					oldKeys = append(oldKeys, key)
					key = b
				}
			}
			if isDisabledBytesK(key, cfg.Except) {
				return
			}
			if cfg.EncryptValue {
				decryptedValue, err := cfg.Decryptor(value, cfg.Key)
				if err != nil {
					if cfg.ReturnOriginalOnError {
						c.Request().Header.SetCookieBytesKV(key, value)
						return
					}
					c.Request().Header.SetCookieBytesKV(key, nil)
					return
				}
				value = decryptedValue
			}
			c.Request().Header.SetCookieBytesKV(key, value)
		})

		if cfg.EncryptKey {
			for _, key := range oldKeys {
				c.Request().Header.DelCookieBytes(key)
			}
			clear(oldKeys)
		}

		// Continue stack
		err := c.Next()

		// Encrypt response cookies
		c.Response().Header.VisitAllCookie(func(key, value []byte) {
			if isDisabledBytesK(key, cfg.Except) {
				return
			}
			encryptedCookie := fasthttp.Cookie{}
			encryptedCookie.SetKeyBytes(key)
			if c.Response().Header.Cookie(&encryptedCookie) {
				if cfg.EncryptKey {
					encryptedKey, err := cfg.Encryptor(encryptedCookie.Key(), cfg.Key)
					if err != nil {
						if cfg.ReturnOriginalOnError {
							c.Response().Header.SetCookie(&encryptedCookie)
							return
						} else {
							panic(err)
						}
					}
					oldKeys = append(oldKeys, key)
					key = encryptedKey
					encryptedCookie.SetKeyBytes(key)
				}
				if cfg.EncryptValue {
					encryptedValue, err := cfg.Encryptor(encryptedCookie.Value(), cfg.Key)
					if err != nil {
						if cfg.ReturnOriginalOnError {
							c.Response().Header.SetCookie(&encryptedCookie)
							return
						} else {
							panic(err)
						}
					}
					value = encryptedValue
				}
				encryptedCookie.SetValueBytes(value)
				c.Response().Header.SetCookie(&encryptedCookie)
			}
		})

		if cfg.EncryptKey {
			for _, key := range oldKeys {
				c.Response().Header.DelCookieBytes(key)
			}
			oldKeys = nil
		}

		return err
	}
}
