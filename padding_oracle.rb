require 'rest-client'

def pad_error?(x)
  puts "Trying #{x}"
  url = "http://crypto-class.appspot.com/po?er=" + x
  resp = RestClient.get(url) { |resp, req, res| res.code.to_i == 404 }
end

class Block
  def initialize(s)
    @bytes = s.scan(/../)
  end

  def []=(i, val)
    @bytes[i] = val
  end

  def [](i)
    @bytes[i]
  end

  def to_s
    @bytes.join
  end

  def to_ascii
    @bytes.collect { |b| b.to_i(16).chr }.join
  end

  def dup
    Block.new(self.to_s)
  end
end

class Attacker

  BYTES_PER_BLOCK = 16
  HEX_CHARS_PER_BLOCK = BYTES_PER_BLOCK * 2
  ASCII_VALS = [32] + (97..122).to_a + (65..96).to_a + (0..31).to_a +
    (33..64).to_a + (123..255).to_a

  def initialize(s)
    @ciphers = s.scan( /#{'.' * HEX_CHARS_PER_BLOCK}/ ).collect do |x|
      Block.new(x)
    end

    @plains = Array.new(@ciphers.size - 1) do
      Block.new(("%02x" % '_'.ord) * BYTES_PER_BLOCK)
    end
  end

  def size
    @ciphers.size
  end

  def decrypt_block(b)
    (1..BYTES_PER_BLOCK).collect do |p|
      exploit_pad b, p
    end.reverse.join
  end

  # Finds plaintext of single byte for given block and pad
  def exploit_pad(b, p)
    puts "Plains is #{plaintext}"
    puts plains_hex
    puts "Exploiting block #{b} with pad value #{p} . . . "
    @guess_block = get_guess_block(b, p)

    ASCII_VALS.each do |i|
      @guess_block[-p] = "%02x" % (i ^ p ^ @ciphers[b][-p].to_i(16))
      if valid? b, @guess_block
        puts "Found #{i} to give a valid pad of #{p}"
        return record(b, p, i)
      end
    end

    # If we didn't find anything, let's hope we were trying to simulate
    # the actual pad
    if (b == @ciphers.size - 2 && p == @plains[b][1-p].to_i(16))
      return record(b, p, p)
    end
  end

  def get_guess_block(b, p)
    guess_block = @ciphers[b].dup

    (2..p).each do |i|
      plain = @plains[b][1-i].to_i(16)
      orig = @ciphers[b][1-i].to_i(16)
      guess_block[1-i] = "%02x" % (p ^ plain ^ orig)
    end

    guess_block
  end

  def record(b, p, i)
    @plains[b][16-p] = "%02x" % i
  end

  def plaintext
    @plains.collect { |block| block.to_ascii }[1..-1].join
  end

  def plains_hex
    @plains.collect { |block| block.to_s }.join
  end

  # Is a valid pad produced when attempting to decrypt block b using @guess_block?
  def valid?(b, guess_block)
    ciphers_to_check = @ciphers[0..b+1]
    ciphers_to_check[-2] = guess_block
    pad_error?(ciphers_to_check.collect { |b| b.to_s }.join)
  end
end

ciphertext = Attacker.new 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'

(ciphertext.size-2).downto(0).each { |b| ciphertext.decrypt_block b }

puts ciphertext.plaintext

