module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;



parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

enum logic [2:0] {IDLE, READ, LAST_READ, BLOCK, COMPUTE, WRITE} state;


logic [31:0] w[64];
logic [31:0] message[20];
logic [31:0] wt;
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a, b, c, d, e, f, g, h;
logic [ 7:0] i, j;
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [31:0] s0; 
logic [31:0] s1; 
logic [ 7:0] p; 
logic [31:0] hh[8];
int t0;
logic [ 4:0] nonce;
logic [31:0] h0_temp[16], h1_temp[16], h2_temp[16], h3_temp[16], h4_temp[16], h5_temp[16], h6_temp[16], h7_temp[16]; //temporary h to store value after second sha256
logic [31:0] h0_f[16], h1_f[16], h2_f[16], h3_f[16], h4_f[16], h5_f[16], h6_f[16], h7_f[16]; //final h to store value after thrid sha256
logic [ 4:0] x;
logic [31:0] h00, h11, h22, h33, h44, h55, h66, h77;




function logic [15:0] determine_num_blocks(input logic [31:0] size);
	
  if (size <= 16) begin determine_num_blocks = 1; end
  else if ((size > 16)&&(size <= 32)) begin determine_num_blocks = 2; end
  else if ((size > 32)&&(size <= 48)) begin determine_num_blocks = 3; end
  else if ((size > 48)&&(size <= 64)) begin determine_num_blocks = 4; end
  else if ((size > 64)&&(size <= 80)) begin determine_num_blocks = 5; end
  
endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w; // ?
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction


assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;
assign hh[0] = h0;
assign hh[1] = h1;
assign hh[2] = h2;
assign hh[3] = h3;
assign hh[4] = h4;
assign hh[5] = h5;
assign hh[6] = h6;
assign hh[7] = h7;


function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction

function logic [31:0] next_w(logic[7:0] t);
 logic [31:0] s1, s0;
 s0 = rightrotate(w[t-15], 7) ^ rightrotate(w[t-15], 18) ^ (w[t-15] >> 3);
 s1 = rightrotate(w[t-2], 17) ^ rightrotate(w[t-2], 19) ^ (w[t-2] >> 10);
 next_w = w[t-16] + s0 + w[t-7] + s1;
endfunction



always_ff @(posedge mem_clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else begin case(state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
       if(start) begin    // initializing
			h0 <= 32'h6a09e667;
         h1 <= 32'hbb67ae85;
         h2 <= 32'h3c6ef372;
         h3 <= 32'ha54ff53a;
         h4 <= 32'h510e527f;
         h5 <= 32'h9b05688c;
         h6 <= 32'h1f83d9ab;
         h7 <= 32'h5be0cd19;
         a <= 0;
         b <= 0;
			c <= 0;
			d <= 0;
			e <= 0;
			f <= 0;
			g <= 0;
			h <= 0;
			cur_we <= 0; 
			offset <= 0; 
			cur_addr <= message_addr; 
			cur_write_data <= 32'h0;
			state <= READ;
			cur_we <= 0;
			nonce <= 0;  //initialized for later usage in SHA256 phase 2 and 3
			x <= 0; //initialized for later usage in LAST_READ
       end
    end
	 
	 
	 READ: begin 
	   if(offset<=19) begin
		  cur_we <= 0;
        if(offset != 0) begin
          message[offset-1] <= mem_read_data;
        end
		  // Increment memory address to fetch next block 
        offset <= offset + 1;
       // stay in read memory state until all input message words are read
        state <= READ;
      end
      else begin
        offset <= 0;
        state <= BLOCK;
		  p <= 0;
      end
    end  
	 
	 LAST_READ: begin
	   h0 <= 32'h6a09e667;
      h1 <= 32'hbb67ae85;
      h2 <= 32'h3c6ef372;
      h3 <= 32'ha54ff53a;
      h4 <= 32'h510e527f;
      h5 <= 32'h9b05688c;
      h6 <= 32'h1f83d9ab;
      h7 <= 32'h5be0cd19;
		x <= x+1;
		a <= 32'h6a09e667;
      b <= 32'hbb67ae85;
      c <= 32'h3c6ef372;
      d <= 32'ha54ff53a;
      e <= 32'h510e527f;
      f <= 32'h9b05688c;
      g <= 32'h1f83d9ab;
      h <= 32'h5be0cd19;
		w[0] <= h0_temp[x];
		w[1] <= h1_temp[x];
		w[2] <= h2_temp[x];
		w[3] <= h3_temp[x];
		w[4] <= h4_temp[x];
		w[5] <= h5_temp[x];
		w[6] <= h6_temp[x];
		w[7] <= h7_temp[x];
		w[8] <= {1'b1, 31'b0};
		for (int n4 = 9; n4 < 14; n4 = n4+1) w[n4] <= 32'b0;
		w[14] <= 32'b0;
	   w[15] <= 32'd256;
		state <= COMPUTE;
		
		
	 end

    
    BLOCK: begin
	 
		j <= 0;
	   if (p < 17) begin         
        if (p == 0) begin     // below is phase 1 (p==0)
          a <= h0;
          b <= h1;	
          c <= h2;
          d <= h3;
          e <= h4;
          f <= h5;
          g <= h6;
          h <= h7;
			 
          for (int n = 0; n < 16; n = n+1) w[n] <= message[n];
			 
        end
		  else if (p == 1) begin    // below is phase 2 (1<=p<17), but p==17 consists of last assignment of h0_temp, h1_temp ....
		    a <= h0;
          b <= h1;
          c <= h2;
          d <= h3;
          e <= h4;
          f <= h5;
          g <= h6;
          h <= h7;
			 
			 h00 <= h0;      //here h00 through h77 are storing value of output of phase 1
			 h11 <= h1;      // because we have to use them as a through h and h0 through h7 as inputs in phase 2
			 h22 <= h2;          
			 h33 <= h3;
			 h44 <= h4;
			 h55 <= h5;
			 h66 <= h6;
			 h77 <= h7;
			 
			 for (int n1 = 16; n1 < 19; n1 = n1+1) w[n1-16] <= message[n1];
			 w[3] <= nonce;
			 w[4] <= {1'b1, 31'b0};
			 for (int n2 = 5; n2 < 14; n2 = n2+1) w[n2] <= 32'b0;
			 w[14] <= 32'b0;
			 w[15] <= 32'd640;
			 
		  end
		  else begin      
		    a <= h00;
			 b <= h11;
			 c <= h22;
			 d <= h33;
			 e <= h44;
			 f <= h55;
			 g <= h66;
			 h <= h77;
			 h0 <= h00;
			 h1 <= h11;
			 h2 <= h22;
			 h3 <= h33;
			 h4 <= h44;
			 h5 <= h55;
			 h6 <= h66;
			 h7 <= h77;
			 
		    w[3] <= p-1;    //updating w[3] each time doing phase 2 iteration
			 nonce <= nonce +1;
			 
			 h0_temp[nonce] <= hh[0];
			 h1_temp[nonce] <= hh[1];
			 h2_temp[nonce] <= hh[2];
			 h3_temp[nonce] <= hh[3];
			 h4_temp[nonce] <= hh[4];
			 h5_temp[nonce] <= hh[5];
			 h6_temp[nonce] <= hh[6];
			 h7_temp[nonce] <= hh[7];
			 
		  end
		  
		  state <= COMPUTE;
		  
      end
		else if (p == 17) begin           // below is phase 3 (17<=p<=33)
		  h0_temp[nonce] <= hh[0];
		  h1_temp[nonce] <= hh[1];
		  h2_temp[nonce] <= hh[2];
	     h3_temp[nonce] <= hh[3];
	  	  h4_temp[nonce] <= hh[4];
		  h5_temp[nonce] <= hh[5];
		  h6_temp[nonce] <= hh[6];
		  h7_temp[nonce] <= hh[7];
		  state <= LAST_READ;
		  nonce <= 0;
		  
		end
		  
      else if (p < 33)begin
		  state <= LAST_READ;
		  h0_f[nonce] <= hh[0];
		  h1_f[nonce] <= hh[1];
		  h2_f[nonce] <= hh[2];
	     h3_f[nonce] <= hh[3];
		  h4_f[nonce] <= hh[4];
		  h5_f[nonce] <= hh[5];
		  h6_f[nonce] <= hh[6];
		  h7_f[nonce] <= hh[7];
		  nonce <= nonce +1;
		end
      else begin
		  h0_f[nonce] <= hh[0];
		  h1_f[nonce] <= hh[1];
		  h2_f[nonce] <= hh[2];
	     h3_f[nonce] <= hh[3];
		  h4_f[nonce] <= hh[4];
		  h5_f[nonce] <= hh[5];
		  h6_f[nonce] <= hh[6];
		  h7_f[nonce] <= hh[7];
		  
        i <= 0;
		  state <= WRITE;
		end
    end
 
    
    COMPUTE: begin	  
		 w[16] <= next_w(16);
		 if (j < 63) begin
         if(j<16) begin 
           {a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[j], j);
         end
         else begin
           w[j+1] <= next_w(j+1); // perform word expansion 
			  {a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[j], j);
			end
			state <= COMPUTE;
			j <= j+1;
		 end
		 else if (j ==63) begin
		   {a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[j], j);
		   state <= COMPUTE;
			j = j+1;
		 end
		 else begin
		   h0 <= h0 + a;
         h1 <= h1 + b;
         h2 <= h2 + c;
         h3 <= h3 + d;
         h4 <= h4 + e;
         h5 <= h5 + f;
         h6 <= h6 + g;
         h7 <= h7 + h;
		   offset <= 0;
		   state <= BLOCK;
		   p <= p + 1;
		end
    end

	 

	 
	WRITE: begin
	   if (i <= 15) begin
	     cur_we <= 1'b1;
		  cur_addr <= output_addr;
	     state <= WRITE;
		  i <= i + 1;
		  offset <= i;
		  cur_write_data <= h0_f[i];
		end
		else begin
		  cur_we <= 1'b0;
		  offset <= 0;
		  state <= IDLE;
		  i <= 0;
		end
    end
   endcase
  end
end

assign done = (state == IDLE);

endmodule