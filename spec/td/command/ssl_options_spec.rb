require 'spec_helper'
require 'td/command/common'
require 'td/config'
require 'td/command/runner'
require 'tempfile'

module TreasureData
  module Command
    describe 'SSL Options' do
      let(:command) { Object.new.extend(TreasureData::Command) }
      let(:config) { TreasureData::Config }
      let(:runner) { TreasureData::Command::Runner.new }
      
      before do
        # Reset environment variables
        ENV.delete('TD_SSL_VERIFY')
        ENV.delete('TD_SSL_CA_FILE')
        
        # Reset class variables
        config.class_variable_set(:@@cl_secure, false)
        config.class_variable_set(:@@cl_ssl_ca_file, false)
        config.class_variable_set(:@@secure, true)
        config.class_variable_set(:@@ssl_ca_file, nil)
      end
      
      describe '#get_client' do
        it 'should use default SSL settings' do
          client_opts = {}
          allow(command).to receive(:validate_ssl_ca_file).and_return(nil)
          allow(config).to receive(:apikey).and_return('dummy_apikey')
          allow(config).to receive(:secure).and_return(true)
          allow(config).to receive(:ssl_ca_file).and_return(nil)
          allow(config).to receive(:retry_post_requests).and_return(false)
          allow(TreasureData::Client).to receive(:new).and_return(double('client'))
          
          command.send(:get_client, client_opts)
          expect(client_opts[:ssl]).to eq(true)
          expect(client_opts).not_to have_key(:ssl_ca_file)
        end
        
        it 'should disable SSL verification when insecure option is used' do
          client_opts = {}
          allow(command).to receive(:validate_ssl_ca_file).and_return(nil)
          allow(config).to receive(:apikey).and_return('dummy_apikey')
          allow(config).to receive(:secure).and_return(false)
          allow(config).to receive(:ssl_ca_file).and_return(nil)
          allow(config).to receive(:retry_post_requests).and_return(false)
          allow(TreasureData::Client).to receive(:new).and_return(double('client'))
          
          command.send(:get_client, client_opts)
          expect(client_opts[:ssl]).to eq(false)
        end
        
        it 'should use custom CA file when provided' do
          client_opts = {}
          ca_file_path = '/path/to/ca_file.pem'
          allow(command).to receive(:validate_ssl_ca_file).and_return(ca_file_path)
          allow(config).to receive(:apikey).and_return('dummy_apikey')
          allow(config).to receive(:secure).and_return(true)
          allow(config).to receive(:ssl_ca_file).and_return(ca_file_path)
          allow(config).to receive(:retry_post_requests).and_return(false)
          allow(TreasureData::Client).to receive(:new).and_return(double('client'))
          
          command.send(:get_client, client_opts)
          expect(client_opts[:ssl]).to eq(true)
          expect(client_opts[:ssl_ca_file]).to eq(ca_file_path)
        end
        
        it 'should raise error when CA file does not exist' do
          client_opts = {}
          ca_file_path = '/nonexistent/ca_file.pem'
          allow(config).to receive(:apikey).and_return('dummy_apikey')
          allow(config).to receive(:secure).and_return(true)
          allow(config).to receive(:ssl_ca_file).and_return(ca_file_path)
          allow(File).to receive(:exist?).with(ca_file_path).and_return(false)
          
          expect {
            command.send(:get_client, client_opts)
          }.to raise_error(ParameterConfigurationError, /SSL CA file not found/)
        end
        
        it 'should raise error when CA file is not readable' do
          client_opts = {}
          ca_file_path = '/unreadable/ca_file.pem'
          allow(config).to receive(:apikey).and_return('dummy_apikey')
          allow(config).to receive(:secure).and_return(true)
          allow(config).to receive(:ssl_ca_file).and_return(ca_file_path)
          allow(File).to receive(:exist?).with(ca_file_path).and_return(true)
          allow(File).to receive(:readable?).with(ca_file_path).and_return(false)
          
          expect {
            command.send(:get_client, client_opts)
          }.to raise_error(ParameterConfigurationError, /SSL CA file not readable/)
        end
      end
      
      describe 'Config' do
        it 'should read SSL verify setting from environment variable' do
          ENV['TD_SSL_VERIFY'] = 'false'
          expect(config.parse_bool_env('TD_SSL_VERIFY')).to eq(false)
          
          ENV['TD_SSL_VERIFY'] = 'true'
          expect(config.parse_bool_env('TD_SSL_VERIFY')).to eq(true)
        end
        
        it 'should read SSL CA file from environment variable' do
          ca_file_path = '/path/to/ca_file.pem'
          ENV['TD_SSL_CA_FILE'] = ca_file_path
          
          # Reset class variables to pick up environment variable
          config.class_variable_set(:@@ssl_ca_file, ENV['TD_SSL_CA_FILE'])
          
          # Mock config file access
          allow(config).to receive(:read).and_raise(ConfigNotFoundError)
          
          expect(config.ssl_ca_file).to eq(ca_file_path)
        end
        
        it 'should read SSL settings from config file' do
          # Mock config file with SSL section
          conf = {
            'ssl.verify' => 'false',
            'ssl.ca_file' => '/path/to/ca_file.pem'
          }
          allow(config).to receive(:read).and_return(conf)
          
          # No environment variables
          ENV.delete('TD_SSL_VERIFY')
          ENV.delete('TD_SSL_CA_FILE')
          
          expect(config.secure).to eq(false)
          expect(config.ssl_ca_file).to eq('/path/to/ca_file.pem')
        end
        
        it 'should prioritize command-line options over environment variables and config file' do
          # Set environment variables
          ENV['TD_SSL_VERIFY'] = 'false'
          ENV['TD_SSL_CA_FILE'] = '/env/ca_file.pem'
          
          # Mock config file
          conf = {
            'ssl.verify' => 'true',
            'ssl.ca_file' => '/config/ca_file.pem'
          }
          allow(config).to receive(:read).and_return(conf)
          
          # Set command-line options
          config.secure = true
          config.ssl_ca_file = '/cmd/ca_file.pem'
          
          expect(config.secure).to eq(true)
          expect(config.ssl_ca_file).to eq('/cmd/ca_file.pem')
        end
      end
      
      describe 'Runner' do
        it 'should parse command-line options correctly' do
          argv = ['--insecure', '--ssl-ca-file', '/path/to/ca_file.pem', 'command']
          
          # Mock methods to prevent actual execution
          allow(runner).to receive(:usage).and_return(0)
          allow(Command::List).to receive(:get_method).and_return([nil, false])
          
          # Run with options
          runner.run(argv)
          
          # Check if options were set correctly
          expect(config.secure).to eq(false)
          expect(config.ssl_ca_file).to eq('/path/to/ca_file.pem')
        end
      end
    end
  end
end