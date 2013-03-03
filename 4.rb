class String
  def ascii_to_i
    self.unpack('H*').first.to_i(16)
  end
end

iv = '20814804c1767293b99f1d9cab3bc3e7'.to_i(16)

old = 'Pay Bob 100$    '.ascii_to_i
new = 'Pay Bob 500$    '.ascii_to_i

puts "%x" % (iv ^ old ^ new)

