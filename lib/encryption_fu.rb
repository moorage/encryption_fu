module EncryptionFu
  
  module ActMethods
    def has_encrypted_fields(options = {})
      
      options[:fields]                  ||= []          # Fields that are to be encrypted (withouth appended string)
      options[:salt_generator]          ||= nil         # Custom method to call (symbol) to generate salt
      options[:salt_field]               ||= :salt       # ActiveRecord field for accessing/saving salt
      options[:encrypted_field_append]   ||= :encrypted  # Appended string to fields for actual storage 
      
      # doing these shenanigans so that the option hash passed in is available to the outside world
      class_inheritable_accessor :encryption_fu_options
      self.encryption_fu_options = options
      
      # only need to define these once on a class
      unless included_modules.include?(InstanceMethods)
        before_validation :generate_and_set_salt
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
          # Writer - passes value through encryption, and sets unencrypted value in instance variable
          self.send :define_method, "#{field_name}=".to_sym do |arg|
            @encryption_fu_attrs ||= Hash.new
            self.send("#{field_name}_#{self.encryption_fu_options[:encrypted_field_append]}=".to_sym, self.encrypt(arg))
            @encryption_fu_attrs[field_name] = arg
          end
        end
      end
  end
  
  module InstanceMethods
    
    protected 
      def crypt(method_sym, cipher_key, plain_text)
        return nil if plain_text.nil?
        cipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
        encryptor = case method_sym
        when :encrypt
          cipher.encrypt
        when :decrypt
          cipher.decrypt
        end
        # encryptor = cipher.send(method_sym)
        encryptor.key = cipher_key
        encryptor.update(plain_text) << encryptor.final      
      end

      def encrypt(text)
        crypt(:encrypt, self.generate_and_set_salt, text)
      end

      def decrypt(text)
        crypt(:decrypt, self.generate_and_set_salt, text)
      end

      # Sets the salt for this (if needed)
      def generate_and_set_salt
        salt_val = self.send self.encryption_fu_options[:salt_field]
        if salt_val.blank?
          if self.encryption_fu_options[:salt_generator]
            salt_val = self.send(encryption_fu_options[:salt_generator])
          else
            salt_val = Digest::SHA1.hexdigest("--#{Time.now.to_s}--#{self.id}--")
          end
          self.send "#{self.encryption_fu_options[:salt_field]}=".to_sym, salt_val
        end
        salt_val
      end
  end
end