class User < ApplicationRecord
    attr_accessor :remember_token, :activation_token
    before_save :downcase_email
    before_create :create_activation_digest
    validates :name, presence: true,
                    uniqueness: { case_sensitive: false },
                    length: {minimum: 3, maximum: 25}
    
    VALID_EMAIL_REGEX = /.+\@.+\..+/i
    
    validates :email, presence: true,
                    uniqueness: { case_sensitive: false },
                    format: { with: VALID_EMAIL_REGEX }
                    
    
    has_secure_password
   # Returns the hash digest of the given string.
   def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end

  def User.new_token
    SecureRandom.urlsafe_base64
  end

  def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end

  def forget
    update_attribute(:remember_digest, nil)
  end

   # Returns true if the given token matches the digest.
   def authenticated?(attribute, token)
    digest = send("#{attribute}_digest")
    return false if digest.nil?
    BCrypt::Password.new(digest).is_password?(token)
  end

  private

  #Converts email to all lower-case
    def downcase_email
        self.email = email.downcase
    end

   # Creates and assigns the activation token and digest.
   def create_activation_digest
    self.activation_token = User.new_token
    self.activation_digest = User.digest(activation_token)
   end

end
