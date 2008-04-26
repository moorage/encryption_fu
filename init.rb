require 'digest/sha1'
require 'encryption_fu'
ActiveRecord::Base.send(:extend, EncryptionFu::ActMethods)