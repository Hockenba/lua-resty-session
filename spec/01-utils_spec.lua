local utils = require "resty.session.utils"


local describe = describe
local tostring = tostring
local random = math.random
local assert = assert
local ipairs = ipairs
local match = string.match
local it = it


describe("Testing utils", function()
  describe("pack/unpack data", function()
    local function range_max(bytes)
      if bytes == 8 then
        bytes = bytes - 1
      end
      return 2 ^ (8 * bytes) - 1
    end

    it("bpack and bunpack produce consistent output", function()
      for _, i in ipairs{ 1, 2, 4, 8 } do
        local input    = random(1, range_max(i))
        local packed   = utils.bpack(i, input)
        local unpacked = utils.bunpack(i, packed)

        assert.equals(i, #packed)
        assert.equals(unpacked, input)
      end
    end)
  end)

  describe("trim", function()
    it("characters are trimmed as expected", function()
      local input = "   \t\t\r\n\n\v\f\f\fyay\ntrim!\f\f\v\n\r\t   "
      local expected_output = "yay\ntrim!"
      local output = utils.trim(input)

      assert.equals(output, expected_output)
    end)
  end)

  describe("encode/decode json", function()
    it("produce consistent output", function()
      local input = {
        foo = "bar",
        test = 123
      }
      local encoded = utils.encode_json(input)
      local decoded = utils.decode_json(encoded)

      assert.same(decoded, input)
    end)
  end)

  describe("encode/decode base64url", function()
    it("produce consistent output", function()
      local input   = "<<<!?>>>?!"
      local encoded = utils.encode_base64url(input)

      assert.is_nil(match(encoded, "[/=+]"))
      local decoded = utils.decode_base64url(encoded)
      assert.equals(input, decoded)
    end)
  end)

  describe("deflate/inflate", function()
    it("produce consistent output", function()
      local input    = utils.rand_bytes(1024)
      local deflated = utils.deflate(input)
      local inflated = utils.inflate(deflated)

      assert.equals(input, inflated)
    end)
  end)

  describe("Derive keys, encrypt and decrypt", function()
    local ikm   = "some key material"
    local nonce = "0000000000000000"
    local usage = "encryption"
    local size  = 44

    it("derives key of expected size with derive_hkdf_sha256", function()
      local k_bytes, err = utils.derive_hkdf_sha256(ikm, nonce, usage, size)
      assert.is_not_nil(k_bytes)
      assert.is_nil(err)
      assert.equals(size, #tostring(k_bytes))
    end)

    it("derives key of expected size with derive_pbkdf2_hmac_sha256", function()
      local k_bytes, err = utils.derive_pbkdf2_hmac_sha256(ikm, nonce, usage, size)
      assert.is_not_nil(k_bytes)
      assert.is_nil(err)
      assert.equals(size, #tostring(k_bytes))
    end)

    it("derives a valid key and calculates mac with it", function()
      local key, err, mac
      key, err = utils.derive_hmac_sha256_key(ikm, nonce)
      assert.is_not_nil(key)
      assert.is_nil(err)
      assert.equals(32, #key)

      mac, err = utils.hmac_sha256(key, "some message")
      assert.is_not_nil(mac)
      assert.is_nil(err)
    end)

    it("successfully derives key and iv; encryption and decryption succeeds", function()
      local data = {
        foo = "bar",
        tab = { "val" },
        num = 123,
      }
      local aad = "some_aad"
      local input_data = utils.encode_json(data)

      local key, err, iv, ciphertext, tag, plaintext
      for _, slow in ipairs({ true, false }) do
        key, err, iv = utils.derive_aes_gcm_256_key_and_iv(ikm, nonce, slow)
        assert.is_not_nil(key)
        assert.is_not_nil(iv)
        assert.is_nil(err)

        ciphertext, err, tag = utils.encrypt_aes_256_gcm(key, iv, input_data, aad)
        assert.is_not_nil(ciphertext)
        assert.is_not_nil(tag)
        assert.is_nil(err)

        plaintext, err = utils.decrypt_aes_256_gcm(key, iv, ciphertext, aad, tag)
        assert.is_not_nil(plaintext)
        assert.is_nil(err)

        assert.equals(plaintext, input_data)
      end
    end)
  end)
  describe("config_fingerprint", function()
    local config_fingerprint = utils.config_fingerprint

    it("gives equal settings the same fingerprint, whichever table they come from", function()
      local one = config_fingerprint({ host = "127.0.0.1", port = 6379, nodes = { { ip = "a" }, { ip = "b" } } })
      local two = config_fingerprint({ nodes = { { ip = "a" }, { ip = "b" } }, port = 6379, host = "127.0.0.1" })

      assert.is_string(one)
      assert.equal(one, two)
    end)

    it("tells different settings apart", function()
      local base = config_fingerprint({ host = "127.0.0.1", port = 6379 })

      assert.not_equal(base, config_fingerprint({ host = "127.0.0.1", port = 6380 }))
      assert.not_equal(base, config_fingerprint({ host = "127.0.0.2", port = 6379 }))
      assert.not_equal(base, config_fingerprint({ host = "127.0.0.1", port = "6379" }))
      assert.not_equal(base, config_fingerprint({ host = "127.0.0.1", port = 6379, ssl = false }))
      assert.not_equal(config_fingerprint({ list = { "a", "b" } }), config_fingerprint({ list = { "b", "a" } }))
      -- a value cannot be moved from one key to the next
      assert.not_equal(config_fingerprint({ a = "bc" }), config_fingerprint({ ab = "c" }))
    end)

    it("leaves out values that are not settings, at any depth", function()
      local plain = config_fingerprint({ host = "127.0.0.1", nested = { port = 6379 } })
      local with_values = config_fingerprint({
        host = "127.0.0.1",
        get = function() end,
        nested = { port = 6379, set = function() end },
      })

      assert.equal(plain, with_values)
    end)

    it("raises an error when cjson cannot sort keys", function()
      local utils_module = package.loaded["resty.session.utils"]
      local cjson_module = package.loaded["cjson.safe"]
      finally(function()
        package.loaded["resty.session.utils"] = utils_module
        package.loaded["cjson.safe"] = cjson_module
      end)

      -- a cjson without encode_sort_keys, as in older OpenResty releases
      package.loaded["cjson.safe"] = {
        new = function()
          return { encode = function() return "{}" end }
        end,
      }
      package.loaded["resty.session.utils"] = nil
      local fresh = require("resty.session.utils")

      local ok, err = pcall(fresh.config_fingerprint, { host = "127.0.0.1" })
      assert.is_false(ok)
      assert.matches("encode_sort_keys", err, 1, true)
    end)

    it("returns an error for a table that refers to itself", function()
      local configuration = { host = "127.0.0.1" }
      configuration.self = configuration

      local fingerprint, err = config_fingerprint(configuration)
      assert.is_nil(fingerprint)
      assert.is_string(err)
    end)
  end)

  describe("get_storage_settings", function()
    it("gives a storage with two names the first one, and the settings of either", function()
      local settings = { host = "127.0.0.1" }
      local preferred = { host = "127.0.0.2" }
      for _, names in ipairs({ { "memcached", "memcache" }, { "mysql", "mariadb" }, { "postgres", "postgresql" } }) do
        local name, alias = names[1], names[2]
        local found_name, found_settings = utils.get_storage_settings(alias, { [alias] = settings })
        assert.equal(name, found_name)
        assert.equal(settings, found_settings)

        found_name, found_settings = utils.get_storage_settings(name, { [alias] = settings })
        assert.equal(name, found_name)
        assert.equal(settings, found_settings)

        -- the settings of the first name are preferred
        found_name, found_settings = utils.get_storage_settings(alias, { [name] = preferred, [alias] = settings })
        assert.equal(name, found_name)
        assert.equal(preferred, found_settings)
      end
    end)

    it("keeps any other name as it is", function()
      local settings = {}
      local name, found_settings = utils.get_storage_settings("custom-storage", { ["custom-storage"] = settings })
      assert.equal("custom-storage", name)
      assert.equal(settings, found_settings)

      name, found_settings = utils.get_storage_settings("redis")
      assert.equal("redis", name)
      assert.is_nil(found_settings)
    end)
  end)

  describe("load_storage", function()
    -- "dshm" is disabled as it currently cannot be checked by CI
    for _, strategy in ipairs({ "memcached", "mysql", "postgres", "redis" }) do
      it("respects pool parameters #" .. strategy, function()
        local storage = assert(utils.load_storage(strategy, {
          [strategy] = {
            pool = "doge",
            pool_size = 10,
            backlog = 20,
          },
        }))

        assert.equal("doge", storage.options.pool)
        assert.equal(10, storage.options.pool_size)
        assert.equal(20, storage.options.backlog)
      end)
    end
    it("respects pool parameters #redis-sentinel", function()
      local storage = assert(utils.load_storage("redis", {
        redis = {
          pool = "doge",
          pool_size = 10,
          backlog = 20,
          sentinels = {},
        },
      }))

      assert.equal("doge", storage.connector.config.connection_options.pool)
      assert.equal(10, storage.connector.config.connection_options.pool_size)
      assert.equal(20, storage.connector.config.connection_options.backlog)
    end)
    it("respects pool parameters #redis-cluster", function()
      local storage = assert(utils.load_storage("redis", {
        redis = {
          pool = "doge",
          pool_size = 10,
          backlog = 20,
          nodes = {},
        },
      }))

      assert.equal("doge", storage.options.connect_opts.pool)
      assert.equal(10, storage.options.connect_opts.pool_size)
      assert.equal(20, storage.options.connect_opts.backlog)
    end)
  end)
end)
