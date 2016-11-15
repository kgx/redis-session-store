require 'redis'
require 'set'

# Redis session storage for Rails, and for Rails only. Derived from
# the MemCacheStore code, simply dropping in Redis instead.
class RedisSessionStore < ActionDispatch::Session::AbstractStore
  VERSION = '0.9.1'.freeze
  DEFAULT_SESSION_PATH = "tmp/redis_session_default.json"
  # Rails 3.1 and beyond defines the constant elsewhere
  unless defined?(ENV_SESSION_OPTIONS_KEY)
    if Rack.release.split('.').first.to_i > 1
      ENV_SESSION_OPTIONS_KEY = Rack::RACK_SESSION_OPTIONS
    else
      ENV_SESSION_OPTIONS_KEY = Rack::Session::Abstract::ENV_SESSION_OPTIONS_KEY
    end
  end

  # ==== Options
  # * +:key+ - Same as with the other cookie stores, key name
  # * +:redis+ - A hash with redis-specific options
  #   * +:url+ - Redis url, default is redis://localhost:6379/0
  #   * +:key_prefix+ - Prefix for keys used in Redis, e.g. +myapp:+
  #   * +:expire_after+ - A number in seconds for session timeout
  #   * +:client+ - Connect to Redis with given object rather than create one
  # * +:on_redis_down:+ - Called with err, env, and SID on Errno::ECONNREFUSED
  # * +:on_session_load_error:+ - Called with err and SID on Marshal.load fail
  # * +:serializer:+ - Serializer to use on session data, default is :marshal.
  #
  # ==== Examples
  #
  #     My::Application.config.session_store :redis_session_store, {
  #       key: 'your_session_key',
  #       redis: {
  #         expire_after: 120.minutes,
  #         key_prefix: 'myapp:session:',
  #         url: 'redis://host:12345/2'
  #       },
  #       on_redis_down: ->(*a) { logger.error("Redis down! #{a.inspect}") }
  #       serializer: :hybrid # migrate from Marshal to JSON
  #     }
  #
  def initialize(app, options = {})
    super

    redis_options = options[:redis] || {}

    @default_options[:namespace] = 'rack:session'
    @default_options.merge!(redis_options)
    @redis = redis_options[:client] || Redis.new(redis_options)
    @on_redis_down = options[:on_redis_down]
    @serializer = determine_serializer(options[:serializer])
    if @serializer == :jsmin
      if File.exist?(DEFAULT_SESSION_PATH)
        @default_session = JSON.try(:parse, open(DEFAULT_SESSION_PATH).read)
      else
        refactor_default_session
      end
    end
    @on_session_load_error = options[:on_session_load_error]
    verify_handlers!
  end

  def refactor_default_session
    n, ar = 0, []
    
    # puts parsed JSON sessions into an array until it gets 10. does not use .try for randomkey, because
    # if that fails, it means the database is empty, which SHOULD throw an error
    ar << JSON.try(:parse, @redis.try(:get, @redis.randomkey)) until ar.length == 10
    ar.compact!
    raise "Not enough valid JSON sessions" if ar.length < 3
    @default_session = ar.inject {|i,e| (i.to_set - e.to_set).to_h}
    File.open(DEFAULT_SESSION_PATH, "w").write(@default_session)
  end
    

  attr_accessor :on_redis_down, :on_session_load_error

  private

  attr_reader :redis, :key, :default_options, :serializer

  # overrides method defined in rack to actually verify session existence
  # Prevents needless new sessions from being created in scenario where
  # user HAS session id, but it already expired, or is invalid for some
  # other reason, and session was accessed only for reading.
  def session_exists?(env)
    value = current_session_id(env)

    !!(
      value && !value.empty? &&
      redis.exists(prefixed(value))
    )
  rescue Errno::ECONNREFUSED, Redis::CannotConnectError => e
    on_redis_down.call(e, env, value) if on_redis_down

    true
  end

  def verify_handlers!
    %w(on_redis_down on_session_load_error).each do |h|
      next unless (handler = public_send(h)) && !handler.respond_to?(:call)

      raise ArgumentError, "#{h} handler is not callable"
    end
  end

  def prefixed(sid)
    "#{default_options[:key_prefix]}#{sid}"
  end

  def get_session(env, sid)
    unless sid && (session = load_session_from_redis(sid))
      sid = generate_sid
      session = {}
    end

    [sid, session.with_indifferent_access]
  rescue Errno::ECONNREFUSED, Redis::CannotConnectError => e
    on_redis_down.call(e, env, sid) if on_redis_down
    [generate_sid, {}.with_indifferent_access]
  end
  alias find_session get_session

  def load_session_from_redis(sid)
    data = redis.get(prefixed(sid))
    begin
      decode(data).with_indifferent_access
    rescue => e
      destroy_session_from_sid(sid, drop: true)
      on_session_load_error.call(e, sid) if on_session_load_error
      {}.with_indifferent_access
    end
  end

  def decode(data)
    serializer.load(data)
  end

  def set_session(env, sid, session_data, options = nil)
    expiry = (options || env.fetch(ENV_SESSION_OPTIONS_KEY))[:expire_after]
    if expiry
      redis.setex(prefixed(sid), expiry, encode(session_data))
    else
      redis.set(prefixed(sid), encode(session_data))
    end
    return sid
  rescue Errno::ECONNREFUSED, Redis::CannotConnectError => e
    on_redis_down.call(e, env, sid) if on_redis_down
    return false
  end
  alias write_session set_session

  def encode(session_data)
    serializer.dump(session_data)
  end

  def destroy_session(env, sid, options)
    destroy_session_from_sid(sid, (options || {}).to_hash.merge(env: env))
  end
  alias delete_session destroy_session

  def destroy(env)
    if env['rack.request.cookie_hash'] &&
       (sid = env['rack.request.cookie_hash'][key])
      destroy_session_from_sid(sid, drop: true, env: env)
    end
    false
  end

  def destroy_session_from_sid(sid, options = {})
    redis.del(prefixed(sid))
    (options || {})[:drop] ? nil : generate_sid
  rescue Errno::ECONNREFUSED, Redis::CannotConnectError => e
    on_redis_down.call(e, options[:env] || {}, sid) if on_redis_down
  end

  def determine_serializer(serializer)
    serializer ||= :marshal
    case serializer
    when :marshal then Marshal
    when :json    then JsonSerializer
    when :jsmin   then JsonMinimizer
    when :hybrid  then HybridSerializer
    else serializer
    end
  end

  # Removes any key-value pairs that are set to their default values, when storing the session, then
  # adds them back in when retrieving the session
  class JsonMinimizer
    def self.load(value)
      if @default_session
        @default_session.merge(JSON.parse(value, quirks_mode: true))
      else
        JSON.parse(value, quirks_mode: true)
      end
    end

    def self.dump(value)
      JSON.generate((value.to_h.to_set - @default_session.to_set).to_h, quirks_mode: true)
    end
  end

  # Uses built-in JSON library to encode/decode session
  class JsonSerializer
    def self.load(value)
      JSON.parse(value, quirks_mode: true)
    end

    def self.dump(value)
      JSON.generate(value, quirks_mode: true)
    end
  end

  # Transparently migrates existing session values from Marshal to JSON
  class HybridSerializer < JsonSerializer
    MARSHAL_SIGNATURE = "\x04\x08".freeze

    def self.load(value)
      if needs_migration?(value)
        Marshal.load(value)
      else
        super
      end
    end

    def self.needs_migration?(value)
      value.start_with?(MARSHAL_SIGNATURE)
    end
  end
end
