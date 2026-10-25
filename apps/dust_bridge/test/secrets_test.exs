defmodule Dust.Bridge.SecretsTest do
  use ExUnit.Case

  alias Dust.Bridge.Secrets

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp_dir} do
    # Stop the application so any supervisor-owned Secrets process is gone
    # before we start a fresh supervised one for this test.
    Application.stop(:dust_bridge)

    old_env = Application.get_env(:dust_utilities, :config, %{})
    variables = ["DUST_COOKIE_FILE", "JOIN_IP", "JOIN_TOKEN"]
    old_variables = Map.new(variables, &{&1, System.get_env(&1)})
    Enum.each(variables, &System.delete_env/1)
    # Point file paths at the test tmp dir
    Application.put_env(:dust_utilities, :config, %{persist_dir: tmp_dir})

    # Start a fresh Secrets agent for each test
    pid = start_supervised!(Secrets)

    on_exit(fn ->
      Enum.each(old_variables, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)

      if old_env do
        Application.put_env(:dust_utilities, :config, old_env)
      else
        Application.delete_env(:dust_utilities, :config)
      end

      Application.ensure_all_started(:dust_bridge)
    end)

    {:ok, agent: pid, tmp_dir: tmp_dir}
  end

  describe "configured bootstrap cookie" do
    test "persists the configured credential instead of generating a new cookie", %{tmp_dir: dir} do
      path = Path.join(dir, "bootstrap.cookie")
      File.write!(path, "configured_cookie\n")
      System.put_env("DUST_COOKIE_FILE", path)

      assert :ok = Secrets.setup()
      assert File.read!(Dust.Utilities.File.secrets_file()) == "configured_cookie"
      assert Secrets.get_fetched_master_key() == nil
    end

    test "preserves a joined cookie across setup even if the configured credential disappears", %{
      tmp_dir: dir
    } do
      path = Path.join(dir, "bootstrap.cookie")
      File.write!(path, "different_cookie")
      System.put_env("DUST_COOKIE_FILE", path)
      :ok = Secrets.adopt_joined_secrets("joined_master_key", "joined_cookie")

      assert :ok = Secrets.setup()
      assert File.read!(Dust.Utilities.File.secrets_file()) == "joined_cookie"
      File.rm!(path)
      assert :ok = Secrets.setup()
      assert File.read!(Dust.Utilities.File.secrets_file()) == "joined_cookie"
    end

    test "does not silently generate a cookie when the configured credential is unreadable", %{
      tmp_dir: dir
    } do
      System.put_env("DUST_COOKIE_FILE", Path.join(dir, "missing.cookie"))

      assert_raise File.Error, fn -> Secrets.setup() end
      refute File.exists?(Dust.Utilities.File.secrets_file())
    end

    test "rejects invalid configured credentials before persisting them", %{tmp_dir: dir} do
      path = Path.join(dir, "bootstrap.cookie")
      System.put_env("DUST_COOKIE_FILE", path)

      for cookie <- [" \n", String.duplicate("x", 256), "two\nlines", "snowman_☃"] do
        File.write!(path, cookie)
        assert_raise ArgumentError, fn -> Secrets.setup() end
        refute File.exists?(Dust.Utilities.File.secrets_file())
      end
    end
  end

  # ── Agent cache (store / get / clear) ─────────────────────────────────

  describe "master key cache" do
    test "initial state is nil" do
      assert Secrets.get_fetched_master_key() == nil
    end

    test "store and retrieve a base-64 master key" do
      key = Base.encode64(:crypto.strong_rand_bytes(32))
      :ok = Secrets.store_fetched_master_key(key)
      assert Secrets.get_fetched_master_key() == key
    end

    test "clear sets the cached key back to nil" do
      Secrets.store_fetched_master_key("some_key")
      assert Secrets.get_fetched_master_key() == "some_key"

      :ok = Secrets.clear_fetched_master_key()
      assert Secrets.get_fetched_master_key() == nil
    end

    test "store overwrites a previously cached key" do
      Secrets.store_fetched_master_key("key_1")
      Secrets.store_fetched_master_key("key_2")
      assert Secrets.get_fetched_master_key() == "key_2"
    end
  end

  # ── get/clear are safe when agent is not running ──────────────────────

  describe "when agent is not running" do
    test "get_fetched_master_key returns nil" do
      stop_supervised!(Secrets)
      assert Secrets.get_fetched_master_key() == nil
    end

    test "clear_fetched_master_key returns :ok" do
      stop_supervised!(Secrets)
      assert Secrets.clear_fetched_master_key() == :ok
    end
  end

  # ── setup/0 — genesis path ────────────────────────────────────────────

  describe "setup/0 genesis path" do
    test "generates a cookie file when no secrets file exists" do
      # Ensure secrets file doesn't exist
      secrets_path = Dust.Utilities.File.secrets_file()
      refute File.exists?(secrets_path)

      Secrets.setup()

      # A cookie file should now exist
      assert File.exists?(secrets_path)

      # Cookie should be a 32-char hex string (16 random bytes)
      cookie = File.read!(secrets_path)
      assert byte_size(cookie) == 32
      assert Regex.match?(~r/^[0-9a-f]{32}$/, cookie)
    end

    test "cookie file has restrictive permissions (0600)", %{tmp_dir: _} do
      Secrets.setup()

      secrets_path = Dust.Utilities.File.secrets_file()
      {:ok, %File.Stat{mode: mode}} = File.stat(secrets_path)
      # 0o100600 = regular file + owner rw only
      assert Bitwise.band(mode, 0o777) == 0o600
    end
  end

  # ── setup/0 — existing cookie path ────────────────────────────────────

  describe "setup/0 existing cookie path" do
    test "loads cookie from disk when secrets file already exists", %{tmp_dir: _} do
      secrets_path = Dust.Utilities.File.secrets_file()
      File.mkdir_p!(Path.dirname(secrets_path))
      File.write!(secrets_path, "existing_test_cookie_value")

      # Should not crash and should load the cookie
      Secrets.setup()

      # Master key cache should remain nil (no join happened)
      assert Secrets.get_fetched_master_key() == nil
    end
  end

  # ── setup/0 — idempotency ─────────────────────────────────────────────

  describe "setup/0 idempotency" do
    test "calling setup twice reuses the existing cookie", %{tmp_dir: _} do
      Secrets.setup()
      secrets_path = Dust.Utilities.File.secrets_file()
      first_cookie = File.read!(secrets_path)

      # Second call should detect the existing file and not overwrite
      Secrets.setup()
      second_cookie = File.read!(secrets_path)

      assert first_cookie == second_cookie
    end
  end
end
