# Expects you to define private_encryption_key method
# Call encrypt_fields any time to read the values from the virtual attributes and encrypt them into their corresponding _encrypted fields.
module EncryptionFu
  
  module ActMethods
    def has_encrypted_fields(options = {})
      
      options[:fields]                  ||= []                      # Fields that are to be encrypted (withouth appended string)
      options[:public_key_field]        ||= :public_encryption_key  # ActiveRecord field for saving public_encryption_key (aka salt)
      options[:encrypted_field_append]  ||= :encrypted              # Appended string to fields for actual storage 
      
      # doing these shenanigans so that the option hash passed in is available to the outside world
      class_inheritable_accessor :encryption_fu_options
      self.encryption_fu_options = options
      
      # only need to define these once on a class
      unless included_modules.include?(InstanceMethods)
        before_validation :encrypt_fields  # Actually encrypts all fields - will make a call to generate_public_encryption_key
        include InstanceMethods
        add_attr_accessors options[:fields]
      end
    end
    private
      def add_attr_accessors(fields)
        fields.each do |field_name|
          # Reader - passes value through decryption if not already set.
          self.send :define_method, field_name do
            @encryption_fu_attrs ||= Hash.new
            if @encryption_fu_attrs[field_name].nil?
              @encryption_fu_attrs[field_name] = 
                self.decrypt(self.send("#{field_name}_#{self.encryption_fu_options[:encrypted_field_append]}".to_sym))
            end
            @encryption_fu_attrs[field_name]
          end
          # Writer - leaves unencrypted until encrypt_fields is called.
          self.send :define_method, "#{field_name}=".to_sym do |arg|
            @encryption_fu_attrs ||= Hash.new
            @encryption_fu_attrs[field_name] = arg
          end
        end
      end
  end
  
  module InstanceMethods
    
    protected 
      def crypt(method_sym, input_text)
        return nil if input_text.blank?
        cipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
        encryptor = case method_sym
        when :encrypt
          cipher.encrypt
        when :decrypt
          cipher.decrypt
        end
        encryptor.key = self.encryption_key
        encryptor.update(input_text) << encryptor.final      
      end

      def encrypt(text)
        result = crypt(:encrypt, text)
        return result.nil? ? result : URI.escape(result) # TODO Un-solvable bug workaround - CipherError
      end

      def decrypt(text)
        text = text.nil? ? text : URI.unescape(text) # TODO Un-solvable bug workaround - CipherError
        crypt(:decrypt, text)
      end

      def generate_public_encryption_key
        Digest::SHA256.hexdigest("-#{Time.now.to_s}-")
      end
      
      # Encrypts a single field, with the current value in its corresponding attr - sets the value into _encrypted.
      def encrypt_field(field_name)
        encrypted_val = self.encrypt(self.send(field_name))
        self.send("#{field_name}_#{self.encryption_fu_options[:encrypted_field_append]}=".to_sym, encrypted_val)
      end
      
      # Encrypts all fields, with the current values set in their corresponding virtual attribute. 
      def encrypt_fields
        self.encryption_fu_options[:fields].each do |field_name|
          self.encrypt_field field_name
        end
      end
      
      # Returns the complete encryption key (sets up a new one if necessary)
      def encryption_key
        return @encryption_fu_attrs['-encryption-key-'] if @encryption_fu_attrs['-encryption-key-']
        
        public_key = self.send self.encryption_fu_options[:public_key_field]
        if public_key.blank?
          public_key = self.generate_public_encryption_key
          self.send "#{self.encryption_fu_options[:public_key_field]}=".to_sym, public_key
        end
        private_key = self.private_encryption_key
        
        @encryption_fu_attrs['-encryption-key-'] = Digest::SHA256.hexdigest("-#{private_key}-#{public_key}-")
      end

  end
end